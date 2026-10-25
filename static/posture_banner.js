// ── Coverage line and score-drop banner on the results ────────────────
// After the results are drawn, one small card at the top of the results says how many
// checks ran ("Coverage: 87% of checks ran") and, when the score fell by at
// least the threshold since the previous assessment of this tenant profile
// (posture_plus, 5 points by default), why: the checks that started
// failing. Both link to Improve my score (/report/posture). Pure
// computation on the server (/api/posture/summary): no tenant read.
(function () {
  'use strict';
  if (window.__postureBanner) return;
  window.__postureBanner = true;

  function css() {
    if (document.getElementById('ppBannerStyle')) return;
    const st = document.createElement('style'); st.id = 'ppBannerStyle';
    st.textContent = '.pp-sum{display:flex;flex-wrap:wrap;gap:0.5rem 1rem;align-items:center;margin:0 0 1rem;padding:0.7rem 1rem;border:1px solid var(--border);border-radius:var(--r-lg,12px);background:var(--card)}'
      + '.pp-sum p{margin:0;flex:1 1 260px;font-size:0.9rem;color:var(--text)}'
      + '.pp-sum .pp-acts{display:flex;gap:0.5rem;flex-wrap:wrap}'
      + '.pp-sum.pp-drop{border-color:var(--warn);background:color-mix(in srgb, var(--warn) 12%, transparent)}'
      + '.pp-sum strong{font-weight:700}'
      + '.pp-sum ul{margin:0.3rem 0 0 1.1rem;padding:0;font-size:0.85rem;color:var(--dim)}';
    document.head.appendChild(st);
  }

  function open(hash) {
    const w = window.open('/report/posture' + (hash || ''), '_blank');
    if (!w) alert('Your browser blocked the new tab. Allow pop-ups for this page and try again.');
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function button(label, hash, aria) {
    const b = el('button', 'btn btn-ghost', label);
    b.type = 'button';
    b.setAttribute('aria-label', aria);
    b.addEventListener('click', () => open(hash));
    return b;
  }

  function host() {
    // Inside the results (so it hides with them on New assessment), right
    // under the download bar: the dashboard moves the score itself above.
    const results = document.getElementById('results');
    if (!results) return null;
    let box = document.getElementById('postureSummary');
    if (!box) {
      box = el('div'); box.id = 'postureSummary';
      box.setAttribute('role', 'status'); box.setAttribute('aria-live', 'polite');
      const bar = results.querySelector('.download-bar');
      if (bar) bar.insertAdjacentElement('afterend', box); else results.insertAdjacentElement('afterbegin', box);
    }
    return box;
  }

  function render(d) {
    const box = host(); if (!box) return;
    css();
    box.textContent = '';
    const alert = d && d.alert;
    const extra = ((d && d.digest_alerts) || []).filter(a => a && a.kind !== 'assessment');
    if (alert) {
      const card = el('div', 'pp-sum pp-drop');
      const p = el('p');
      const when = alert.previous_at ? new Date(alert.previous_at).toLocaleDateString() : 'the previous run';
      p.appendChild(el('strong', '', `Score drop: ${alert.from}% → ${alert.to}% since ${when}. `));
      p.appendChild(document.createTextNode(alert.sentence || ''));
      const failing = (alert.newly_failing || []).slice(0, 3);
      if (failing.length) {
        const ul = el('ul');
        failing.forEach(c => ul.appendChild(el('li', '', `${c.id} ${c.label}: ${c.from} → ${c.to}`)));
        if ((alert.newly_failing || []).length > 3) ul.appendChild(el('li', '', `and ${alert.newly_failing.length - 3} more`));
        p.appendChild(ul);
      }
      const acts = el('div', 'pp-acts');
      acts.appendChild(button('See what changed', '#trend', 'See what changed since the previous assessment (opens Improve my score in a new tab)'));
      card.append(p, acts);
      box.appendChild(card);
    }
    extra.forEach(a => {
      const card = el('div', 'pp-sum pp-drop');
      card.appendChild(el('p', '', `${a.what}: ${a.from}% → ${a.to}% (digest ${a.digest || ''}). ${a.sentence || ''}`));
      box.appendChild(card);
    });
    const cov = d && d.coverage;
    if (cov && cov.total) {
      const card = el('div', 'pp-sum');
      card.appendChild(el('p', '', cov.sentence || ''));
      const acts = el('div', 'pp-acts');
      if (cov.not_ran || cov.hidden) acts.appendChild(button('What could not be checked', '#coverage', 'What the assessment could not check, why, and how to fix it (opens in a new tab)'));
      acts.appendChild(button('Improve my score', '', 'Open Improve my score: the fixes that raise the score most (opens in a new tab)'));
      card.appendChild(acts);
      box.appendChild(card);
    }
    box.hidden = !box.childNodes.length;
  }

  async function refresh(data) {
    if (!data || !Array.isArray(data.checks) || !data.checks.length) return;
    const checks = data.checks.map(c => ({ id: c.id, sec: c.sec, section: c.section, label: c.label, status: c.status,
      detail: String(c.detail || '').slice(0, 600), out_of_scope: c.out_of_scope, channel: c.channel }));
    const body = { checks, hidden_checks: Number(data.hidden_checks) || 0, channel_coverage: data.channel_coverage || null,
      profile_id: (window.GD && GD.profile) ? GD.profile : '' };
    try {
      const r = await fetch('/api/posture/summary', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) return;
      render(await r.json());
    } catch (e) { /* the results stand on their own; this line is extra */ }
  }
  window.__postureRefresh = refresh;

  const orig = window.showResults;
  if (typeof orig !== 'function') return;
  window.showResults = function (data) {
    const out = orig.apply(this, arguments);
    try { refresh(data); } catch (e) { /* ignore */ }
    return out;
  };
})();
