/* Path analyzer: ZPA first, and traffic from a workload.
 *
 * Adds to the Path analyzer page (static/report_path.html):
 * - "Traffic from" (a user device or a workload), the port, and the
 *   workload's source IP, tags, workload group and connector group;
 * - PathZpa.fetch: the page's own fetch for its IIFE. A start of the
 *   analysis (/api/path-analyzer/start) goes to /api/path-analyzer/full/start
 *   with these fields added; every other request passes through unchanged.
 *   The answer has the same shape, so the page renders it as before;
 * - PathZpa.decorate(res): the ZPA and connector module hops
 *   ({module, verdict, rule: {name, order}, overlaps, criteria, notes}) as
 *   one table, right under the verdict.
 * Nothing here reads the tenant by itself or stores anything.
 */
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  if (typeof DF_STATUS === 'object') {
    Object.assign(DF_STATUS, {
      zpa_allowed: ['Carried by ZPA', 'ok'], zpa_denied: ['Blocked by ZPA', 'block'], zpa_conditional: ['Depends on the user', 'dim'],
    });
  }
  if (typeof DF_OUTCOME === 'object') {
    Object.assign(DF_OUTCOME, {
      zpa_allowed: ['Carried by ZPA and allowed: ZIA does not apply', 'ok'], zpa_denied: ['Blocked by ZPA: ZIA does not apply', 'block'],
      zpa_conditional: ['ZPA: depends on the user or device', 'dim'],
    });
  }
  const VERDICT = {
    matched: ['Matches', 'ok'], not_matched: ['No match', 'dim'], allowed: ['Allowed', 'ok'], denied: ['Denied', 'block'],
    bypassed: ['Bypasses', 'warn'], intercepted: ['Intercepted', 'ok'], forwarded: ['Forwarded', 'ok'], dropped: ['Dropped', 'block'],
    conditional: ['Conditional', 'warn'], unknown: ['Unable to verify', 'dim'], not_reached: ['Not reached', 'dim'],
    not_in_scope: ['Not in scope', 'dim'], carried: ['Carried', 'ok'],
  };
  const STATE = { match: ['Met', 'ok'], nomatch: ['Not met', 'dim'], unknown: ['Unknown', 'warn'] };
  const ids = { zpa: '', ztw: '' };

  function mount() {
    const nav = document.querySelector('nav.rp-bar');
    const plat = document.getElementById('paPlat');
    if (!nav || !plat || document.getElementById('paSource')) return;
    const anchor = plat.closest('label');
    anchor.insertAdjacentHTML('afterend',
      `<label class="df-ctl"><span class="lbl">Traffic from</span><select id="paSource" aria-label="Where the traffic comes from" aria-describedby="paSourceHow">
         <option value="device">A user device (Client Connector)</option><option value="workload">A workload (Cloud or Branch Connector)</option></select></label>
       <label class="df-ctl"><span class="lbl">Port</span><input type="text" id="paPort" inputmode="numeric" maxlength="5" placeholder="443" aria-label="Destination port (optional; 443 for https)" autocomplete="off"></label>`);
    nav.insertAdjacentHTML('afterend',
      `<div class="rp-bar pa-workload" id="paWorkload" role="group" aria-label="The workload" hidden>
         <label class="df-ctl"><span class="lbl">Source IP</span><input type="text" id="paWlIp" maxlength="45" placeholder="10.1.2.3" aria-label="The workload's source IP address" autocomplete="off" spellcheck="false"></label>
         <label class="df-ctl"><span class="lbl">Tags</span><input type="text" id="paWlTags" maxlength="2000" placeholder="VPC: Vpc-id=vpc-123, Env=prod" aria-label="The workload's tags: key=value, comma separated, optionally with a type such as VPC: or VM:" autocomplete="off" spellcheck="false"></label>
         <label class="df-ctl"><span class="lbl">Workload group</span><input type="text" id="paWlGroup" maxlength="200" placeholder="optional" aria-label="The workload group, if you know it (optional)" autocomplete="off"></label>
         <label class="df-ctl"><span class="lbl">Connector group</span><input type="text" id="paWlEc" maxlength="200" placeholder="optional" aria-label="The Cloud or Branch Connector group the workload sits behind (optional)" autocomplete="off"></label>
       </div>`);
    const how = document.getElementById('paHow');
    (how || nav).insertAdjacentHTML(how ? 'beforeend' : 'afterend',
      `<p class="df-hint" id="paSourceHow">ZPA is checked first when ZPA is ticked on the Scope page: a destination ZPA carries never reaches ZIA. For a workload, tick Cloud &amp; Branch Connector: its forwarding rules decide whether the traffic goes to ZIA, ZPA, direct or is dropped.</p>`);
    const src = document.getElementById('paSource');
    const sync = () => {
      const wl = src.value === 'workload';
      // style.display as well as hidden: the bar's and controls' own display rules would show them.
      const show = (el, on) => { if (el) { el.hidden = !on; el.style.display = on ? '' : 'none'; } };
      show(document.getElementById('paWorkload'), wl);
      ['paNet', 'paPlat'].forEach(id => show(document.getElementById(id).closest('label'), !wl));
    };
    src.addEventListener('change', sync);
    const q = new URLSearchParams(location.search);
    if (q.get('src') === 'workload') src.value = 'workload';
    if (/^\d{1,5}$/.test(q.get('port') || '')) document.getElementById('paPort').value = q.get('port');
    sync();
  }

  function val(id) { const el = document.getElementById(id); return el ? el.value.trim() : ''; }
  function payload() {
    const fresh = (document.getElementById('paFresh') || {}).getAttribute && document.getElementById('paFresh').getAttribute('aria-pressed') === 'true';
    const source = val('paSource') || 'device';
    const out = { source, port: val('paPort'), protocol: 'tcp', zpa_report_id: fresh ? '' : ids.zpa, ztw_report_id: fresh ? '' : ids.ztw };
    if (source === 'workload') out.workload = { ip: val('paWlIp'), tags: val('paWlTags'), workload_group: val('paWlGroup'), connector_group: val('paWlEc') };
    return out;
  }

  function pzFetch(url, opts) {
    if (url === '/api/path-analyzer/start' && opts && typeof opts.body === 'string') {
      let body;
      try { body = JSON.parse(opts.body); } catch (e) { return window.fetch(url, opts); }
      return window.fetch('/api/path-analyzer/full/start', Object.assign({}, opts, { body: JSON.stringify(Object.assign(body, payload())) }));
    }
    return window.fetch(url, opts);
  }

  function chip(map, key) { const [lab, cls] = map[key] || [key, 'dim']; return `<span class="df-chip st-${E(cls)}">${E(lab)}</span>`; }
  function modulesHtml(mods) {
    const rows = mods.map(m => `<tr>
        <th scope="row">${E(m.module)}</th>
        <td>${chip(VERDICT, m.verdict)}</td>
        <td>${m.rule && m.rule.name ? `<code>${E(m.rule.name)}</code>${m.rule.order != null ? ` <span class="df-by">order ${E(m.rule.order)}</span>` : ''}` : '—'}</td>
        <td>${(m.criteria || []).length ? `<ul class="df-rules">${m.criteria.map(c => `<li>${chip(STATE, c.state)} ${E(c.name)}</li>`).join('')}</ul>` : '—'}</td>
        <td>${(m.notes || []).map(n => `<div class="df-hop-d">${E(n)}</div>`).join('')}${(m.overlaps || []).length
          ? `<details><summary>${m.overlaps.length} overlapping ${m.overlaps.length === 1 ? 'rule or segment' : 'rules or segments'}</summary><ul class="df-rules">${m.overlaps.map(o => `<li>${E(o)}</li>`).join('')}</ul></details>` : ''}</td>
      </tr>`).join('');
    return `<section class="pa-modules" aria-labelledby="paModulesH">
        <h2 class="df-h" id="paModulesH">Before ZIA: ZPA and the connector</h2>
        <p class="df-hint">What decides the traffic before ZIA, in the order it is applied. A criterion marked Unknown depends on something you did not give, or on a condition this page cannot evaluate.</p>
        <div class="df-tablewrap"><table class="df-table pa-modules-table"><caption class="sr-only">ZPA and connector decisions, in order</caption>
          <thead><tr><th scope="col">Step</th><th scope="col">Verdict</th><th scope="col">Rule</th><th scope="col">Criteria</th><th scope="col">Notes</th></tr></thead>
          <tbody>${rows}</tbody></table></div>
      </section>`;
  }
  function decorate(res) {
    if (!res) return;
    if (res.zpa_report_id) ids.zpa = res.zpa_report_id;
    if (res.ztw_report_id) ids.ztw = res.ztw_report_id;
    const mods = res.modules || [];
    const body = document.getElementById('paBody');
    const verdict = body && body.querySelector('.pa-verdict');
    if (!verdict || !mods.length) return;
    verdict.insertAdjacentHTML('afterend', modulesHtml(mods));
    if (res.source === 'workload') {
      const top = verdict.querySelector('.pa-verdict-top .df-by');
      if (top) top.textContent = `${res.destination && res.destination.input || ''} · from a workload`;
    }
  }

  window.PathZpa = { fetch: pzFetch, decorate, payload, mount, modulesHtml };
  mount();
})();
