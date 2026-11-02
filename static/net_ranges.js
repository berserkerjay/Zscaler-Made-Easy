/* Zscaler IP ranges and allowlists (/report/exports, section #exRanges).
 * The switch, Fetch now, Import and Forget call /api/zscaler-ranges/*
 * (the server alone talks to config.zscaler.com, and only when the switch
 * is on and Fetch now is clicked). Build and the downloads use the kept
 * feeds only. Every value from the server is escaped or set as text. */
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  if (!$('exRanges')) return;
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x;
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  const day = iso => String(iso || '').slice(0, 10) || 'an unknown date';
  const DOWNLOADS = ['exRgTxt', 'exRgCsv', 'exRgEdlIp', 'exRgEdlUrl', 'exRgJson', 'exRgM365'];
  const MAX_FILE = 4 * 1024 * 1024;
  let st = null, said = '', lastBody = null;

  function setEnabled(id, on) { const b = $(id); if (b) { b.disabled = !on; b.setAttribute('aria-disabled', on ? 'false' : 'true'); } }
  async function call(method, path, body) {
    const opt = { method, cache: 'no-store' };
    if (body) { opt.headers = { 'Content-Type': 'application/json' }; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(errText(d, r.status));
    return d;
  }
  function choice() {
    return {
      cloud: $('exRgCloud').value || 'zscaler.net', zpa_cloud: $('exRgZpa').value || null,
      feeds: Array.from(document.querySelectorAll('input[name="exRgFeed"]:checked')).map(x => x.value),
    };
  }
  function keptFor() {
    const c = choice();
    return ((st && st.kept) || []).filter(k => k.cloud === c.cloud || (c.zpa_cloud && k.cloud === c.zpa_cloud));
  }

  function drawBox() {
    const rows = [];
    const kept = keptFor();
    rows.push(`Fetching from <code>${E(st.host)}</code>: ${st.enabled ? '<span class="rg-on">On</span> (only when you click Fetch now)' : '<span class="rg-off">Off</span>'}`
      + (st.last_error ? ` <span class="rg-warn">Last try: ${E(st.last_error)}</span>` : ''));
    if (!kept.length) rows.push('<strong>No feed is kept for this cloud.</strong> Fetch or import the feeds, then build the allowlist.');
    kept.forEach(k => rows.push(`<strong>${E(k.label)}</strong> (${E(k.cloud)}): ${k.source === 'imported' ? 'imported' : 'fetched'} ${E(day(k.fetched_at))}, `
      + `${E(k.ipv4)} IPv4 and ${E(k.ipv6)} IPv6 range(s), ${E(k.hosts)} host name(s)${k.rejected ? `, ${E(k.rejected)} entry(ies) dropped` : ''}`
      + (k.stale ? ` <span class="rg-warn">Stale: ${E(k.age_days)} days old, more than ${E(st.max_age_days)}.</span>` : '')));
    if (said) rows.push(`<span>${E(said)}</span>`);
    $('exRgBox').innerHTML = rows.map(r => `<div>${r}</div>`).join('');
    $('exRgFetchOn').checked = !!st.enabled;
    setEnabled('exRgFetch', !!st.enabled);
    setEnabled('exRgRemove', !!(st.kept || []).length);
    drawRegions();
  }
  function drawRegions() {
    const box = $('exRgRegions');
    const was = new Set(Array.from(box.querySelectorAll('input[name="exRgRegion"]:checked')).map(x => x.value));
    const names = [...new Set(keptFor().flatMap(k => k.regions || []))].sort();
    const legend = box.querySelector('legend').outerHTML;
    box.innerHTML = legend + (names.length ? names.map(n => `<label><input type="checkbox" name="exRgRegion" value="${E(n)}"${was.has(n) ? ' checked' : ''}> ${E(n)}</label>`).join('')
      : '<span class="df-by">No region yet: fetch or import a feed.</span>');
  }
  function drawFeeds() {
    const f = $('exRgFeeds');
    const legend = f.querySelector('legend').outerHTML;
    f.innerHTML = legend + st.feeds.map(x => `<label><input type="checkbox" name="exRgFeed" value="${E(x.key)}" checked> ${E(x.label)}${x.product === 'zpa' ? ' (ZPA)' : ''}</label>`).join('');
    $('exRgImpFeed').innerHTML = st.feeds.map(x => `<option value="${E(x.key)}">${E(x.label)}</option>`).join('');
    zpaState();
  }
  function zpaState() {
    const on = !!$('exRgZpa').value;
    const box = document.querySelector('input[name="exRgFeed"][value="zpa"]');
    if (box) { box.disabled = !on; if (!on) box.checked = false; else if (!box.dataset.touched) box.checked = true; }
  }
  async function load(msg) {
    said = msg || '';
    try {
      const first = !st;
      st = await call('GET', '/api/zscaler-ranges');
      if (first) {
        $('exRgCloud').innerHTML = st.zia_clouds.map(c => `<option value="${E(c)}">${E(c)}</option>`).join('');
        $('exRgZpa').innerHTML = '<option value="">None</option>' + st.zpa_clouds.map(c => `<option value="${E(c)}">${E(c)}</option>`).join('');
        drawFeeds();
      }
      drawBox();
    } catch (e) { $('exRgBox').textContent = `Could not read the setting: ${e.message}`; }
  }

  $('exRgCloud').addEventListener('change', () => { if (st) drawBox(); });
  $('exRgZpa').addEventListener('change', () => { zpaState(); if (st) drawBox(); });
  $('exRgFeeds').addEventListener('change', e => { if (e.target && e.target.value === 'zpa') e.target.dataset.touched = '1'; });
  $('exRgFetchOn').addEventListener('change', async e => {
    try { st = await call('PUT', '/api/zscaler-ranges/settings', { enabled: e.target.checked });
      said = e.target.checked ? 'Fetching is on. Nothing is fetched until you click Fetch now.' : 'Fetching is off. Feeds already kept are still used.'; drawBox(); }
    catch (err) { e.target.checked = !e.target.checked; load(`Not changed: ${err.message}`); }
  });
  $('exRgFetch').addEventListener('click', async () => {
    const c = choice();
    if (!c.feeds.length) { load('Tick at least one feed.'); return; }
    setEnabled('exRgFetch', false);
    $('exRgBox').insertAdjacentHTML('beforeend', '<div class="df-by">Fetching from config.zscaler.com…</div>');
    try {
      const d = await call('POST', '/api/zscaler-ranges/fetch', c);
      const bad = (d.results || []).filter(r => !r.ok);
      st = d.status;
      said = `Fetched ${(d.results || []).length - bad.length} feed(s).` + (bad.length ? ` Not fetched: ${bad.map(r => `${r.feed} (${r.error})`).join('; ')}` : '');
      drawBox();
    } catch (e) { load(e.message); }
  });
  $('exRgImport').addEventListener('click', () => {
    const f = ($('exRgFile').files || [])[0];
    if (!f) { load('Choose the file first: the JSON saved from the feed\'s address.'); $('exRgFile').focus(); return; }
    if (f.size > MAX_FILE) { load('That file is larger than 4 MB, so it is not a Zscaler feed.'); return; }
    const feed = $('exRgImpFeed').value;
    const meta = (st.feeds || []).find(x => x.key === feed) || {};
    const cloud = meta.product === 'zpa' ? $('exRgZpa').value : $('exRgCloud').value;
    if (!cloud) { load('Pick the ZPA cloud first: the ZPA allow list is kept per ZPA cloud.'); return; }
    const r = new FileReader();
    r.onload = async () => {
      try { const d = await call('POST', '/api/zscaler-ranges/import', { feed, cloud, content: String(r.result || '') });
        load(`Imported ${d.label} for ${d.cloud}: ${d.ranges} range(s), ${d.hosts} host name(s)${d.rejected ? `, ${d.rejected} entry(ies) dropped` : ''}.`); }
      catch (e) { load(e.message); }
    };
    r.onerror = () => load('The file could not be read.');
    r.readAsText(f);
  });
  $('exRgRemove').addEventListener('click', async () => {
    const ok = window.dlpDialog ? await window.dlpDialog.ask({ title: 'Forget the kept feeds?', body: 'Every kept Zscaler IP range feed is removed from this computer. Allowlists say unknown until you fetch or import them again.', okLabel: 'Forget', tone: 'bad' })
                                : window.confirm('Forget the kept feeds?');
    if (!ok) return;
    try { st = await call('DELETE', '/api/zscaler-ranges'); said = 'Forgotten.'; drawBox(); clearResult(); }
    catch (e) { load(e.message); }
  });

  function body() {
    return Object.assign(choice(), {
      regions: Array.from(document.querySelectorAll('input[name="exRgRegion"]:checked')).map(x => x.value),
      exclude: $('exRgExclude').value, extra: $('exRgExtra').value, ipv4: $('exRgV4').checked, ipv6: $('exRgV6').checked,
    });
  }
  function clearResult() { lastBody = null; $('exRgOut').innerHTML = ''; DOWNLOADS.forEach(id => setEnabled(id, false)); }
  function drawResult(d) {
    const parts = [];
    parts.push(`<p><strong>${E(d.counts.ipv4)} IPv4 and ${E(d.counts.ipv6)} IPv6 range(s)</strong> after aggregation (from ${E(d.counts.in)}), ${E(d.counts.hosts)} host name(s), `
      + `${E(d.counts.excluded)} range(s) left out, ${E(d.counts.added)} added. Cloud ${E(d.cloud)}${d.zpa_cloud ? `, ZPA ${E(d.zpa_cloud)}` : ''}; built ${E(day(d.built_at))}.</p>`);
    (d.warnings || []).forEach(w => parts.push(`<div class="bp-card warn" role="note"><div>${E(w)}</div></div>`));
    parts.push('<div class="df-tablewrap"><table class="df-table"><caption>Where each feed came from</caption><thead><tr><th scope="col">Feed</th><th scope="col">State</th><th scope="col">From</th><th scope="col">Changes since the copy before</th></tr></thead><tbody>'
      + d.sources.map(s => `<tr><td>${E(s.label)} (${E(s.cloud)})<br><code>${E(s.url)}</code></td><td>${E({ ok: 'Current', stale: 'Stale', missing: 'Unknown: not kept' }[s.status] || s.status)}</td>`
        + `<td>${s.fetched_at ? `${E(s.source === 'imported' ? 'Imported' : 'Fetched')} ${E(day(s.fetched_at))}` : '—'}</td>`
        + `<td>${s.previous_at ? `${E(s.added_total)} added, ${E(s.removed_total)} removed since ${E(day(s.previous_at))}` : '—'}</td></tr>`).join('') + '</tbody></table></div>');
    parts.push('<div class="df-tablewrap"><table class="df-table"><caption>Per region, aggregated</caption><thead><tr><th scope="col">Region</th><th scope="col">Ranges in</th><th scope="col">IPv4</th><th scope="col">IPv6</th></tr></thead><tbody>'
      + d.regions.map(r => `<tr><td>${E(r.region)}</td><td>${E(r.in)}</td><td>${E(r.ipv4.length)}</td><td>${E(r.ipv6.length)}</td></tr>`).join('') + '</tbody></table></div>');
    const all = d.all.ipv4.concat(d.all.ipv6);
    if (all.length) parts.push(`<details><summary>All ranges (${E(all.length)})</summary><pre class="ex-rg-pre" tabindex="0">${E(all.slice(0, 2000).join('\n'))}${all.length > 2000 ? '\n…' : ''}</pre></details>`);
    $('exRgOut').innerHTML = parts.join('');
  }
  $('exRgBuild').addEventListener('click', async () => {
    setEnabled('exRgBuild', false);
    try {
      const b = body();
      const d = await call('POST', '/api/zscaler-ranges/build', b);
      lastBody = b; drawResult(d);
      const any = d.counts.ipv4 + d.counts.ipv6 + d.counts.hosts > 0;
      DOWNLOADS.forEach(id => setEnabled(id, any));
    } catch (e) { clearResult(); $('exRgOut').innerHTML = `<div class="bp-card risk" role="alert"><div class="t">Not built</div><div>${E(e.message)}</div></div>`; }
    finally { setEnabled('exRgBuild', true); }
  });
  DOWNLOADS.forEach(id => $(id).addEventListener('click', async () => {
    if (!lastBody) return;
    const fmt = $(id).dataset.rgFmt;
    try {
      const r = await fetch('/api/zscaler-ranges/download', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({}, lastBody, { format: fmt })) });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(errText(d, r.status)); }
      const cd = r.headers.get('Content-Disposition') || '';
      const name = ((cd.match(/filename="?([^";]+)"?/) || [])[1]) || `zscaler_ranges_${fmt}.txt`;
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) { $('exRgOut').insertAdjacentHTML('afterbegin', `<div class="bp-card risk" role="alert"><div>${E(e.message)}</div></div>`); }
  }));
  load();
}());
