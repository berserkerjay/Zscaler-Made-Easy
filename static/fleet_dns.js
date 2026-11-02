/* DNS records for client hostnames (/report/fleet, section #zfDns): after a
 * fleet read with enrolled devices, POST /api/zcc/fleet/{job}/dns-records
 * builds Unbound, BIND, Windows DNS (PowerShell, dnscmd) and CSV text from that read (no tenant call) and the
 * buttons save it as files. Nothing is sent to a DNS server. Every value
 * from the server is set as text or escaped. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x;
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  if (!$('zfDns')) return;
  let job = null, built = null;
  const DL = { zfDnsUnbound: 'unbound', zfDnsNamed: 'bind_forward', zfDnsZone: 'bind_zone', zfDnsWinPs: 'windows_ps', zfDnsWinCmd: 'windows_dnscmd', zfDnsCsv: 'csv' };
  const STATUS = { ok: 'OK', renamed: 'Renamed', duplicate: 'Duplicate', collision: 'Collision', invalid: 'No usable name', reserved: 'Reserved name', 'too long': 'Too long' };

  function setEnabled(id, on) { const b = $(id); if (b) { b.disabled = !on; b.setAttribute('aria-disabled', on ? 'false' : 'true'); } }
  function status(t, bad) { const s = $('zfDnsStatus'); s.textContent = t; s.classList.toggle('bad', !!bad); }
  function downloads(on) { Object.keys(DL).forEach(id => setEnabled(id, on)); }

  document.addEventListener('zf-fleet-read', ev => {
    const d = ev.detail || {};
    job = d.devices ? d.job : null;
    built = null; downloads(false); $('zfDnsOut').innerHTML = '';
    setEnabled('zfDnsBuild', !!job);
    status(job ? `${d.devices} device(s) from the fleet read${d.truncated ? ' (only part of the device list was kept, so the files would be incomplete)' : ''}. Type the domain and the resolver addresses, then Build the records.`
               : 'This fleet read has no enrolled devices (the API client may not read them), so there are no hostnames to write.', !job);
  });

  function body() {
    const seen = $('zfDnsSeen').value.trim();
    return {
      domain: $('zfDnsDomain').value.trim(), resolvers: $('zfDnsResolvers').value.trim(),
      platforms: Array.from(document.querySelectorAll('input[name="zfDnsPlat"]:checked')).map(x => x.value),
      registered_only: $('zfDnsRegistered').checked, seen_within_days: seen ? Number(seen) : null,
      mappings: $('zfDnsMap').value, ttl: Number($('zfDnsTtl').value || 300),
      unbound_local_zone: $('zfDnsLocalZone').checked, unbound_insecure: $('zfDnsInsecure').checked,
    };
  }

  function table(caption, head, rows) {
    if (!rows.length) return '';
    return `<div class="tw"><table class="zf-t"><caption>${E(caption)}</caption><thead><tr>${head.map(h => `<th scope="col">${E(h)}</th>`).join('')}</tr></thead>`
      + `<tbody>${rows.map(r => `<tr>${r.map(c => `<td>${E(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  }

  function render(d) {
    const c = d.counts || {};
    const parts = [];
    parts.push(`<p><strong>${E(c.records)} name(s)</strong> under ${E(d.meta.domain)}${(d.meta.mappings || []).length ? ' and the mapped domains' : ''}, sent to ${E((d.meta.resolvers || []).join(', '))}. `
      + `${E(c.considered)} of ${E(c.devices)} device(s) considered; ${E(c.renamed)} renamed, ${E(c.duplicates)} duplicate(s), ${E(c.collisions)} collision(s), `
      + `${E((c.invalid || 0) + (c.reserved || 0) + (c.too_long || 0))} without a usable name.</p>`);
    (d.warnings || []).forEach(w => parts.push(`<div class="bp-card warn" role="note"><div>${E(w)}</div></div>`));
    parts.push(table('Collisions: different hostnames that give the same name (written once)', ['Name', 'Hostnames'],
      (d.collisions || []).map(x => [x.fqdn, x.hostnames.join(', ')])));
    parts.push(table('Duplicates: the same hostname on more than one enrolment (written once)', ['Name', 'Hostname', 'Extra enrolments'],
      (d.duplicates || []).map(x => [x.fqdn, x.hostname, x.extra_enrolments])));
    parts.push(table('Not written', ['Hostname', 'Domain', 'Why'], (d.refused || []).map(x => [x.hostname, x.domain, `${STATUS[x.status] || x.status}: ${x.note}`])));
    parts.push(table(`Names${d.rows_total > (d.preview || []).length ? ` (first ${(d.preview || []).length} of ${d.rows_total}; the CSV has them all)` : ''}`,
      ['Hostname', 'Name', 'Status', 'Note'], (d.preview || []).map(x => [x.hostname, x.fqdn || '—', STATUS[x.status] || x.status, x.note])));
    $('zfDnsOut').innerHTML = parts.join('');
  }

  $('zfDnsBuild').addEventListener('click', async () => {
    if (!job) return;
    setEnabled('zfDnsBuild', false); status('Building…');
    try {
      const r = await fetch(`/api/zcc/fleet/${encodeURIComponent(job)}/dns-records`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body()) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(errText(d, r.status));
      built = d; render(d); downloads(true);
      status(`Built ${d.counts.records} name(s). Download the files you need and load them on your DNS server yourself.`);
    } catch (e) {
      built = null; downloads(false); $('zfDnsOut').innerHTML = ''; status(`Not built: ${e.message}`, true);
    } finally { setEnabled('zfDnsBuild', !!job); }
  });

  Object.entries(DL).forEach(([id, key]) => $(id).addEventListener('click', () => {
    if (!built || !built.files || built.files[key] == null) return;
    const name = (built.file_names || {})[key] || `zcc_${key}.txt`;
    const blob = new Blob([built.files[key]], { type: key === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    status(`Saved ${name}.`);
  }));
}());
