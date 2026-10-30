// Advanced settings: this app's quality and security score (GET
// /api/quality-score, the docs/quality_score.json that
// tools/quality_score.py builds). Read-only. Every value from the file is
// escaped before it is drawn; bar widths are set through the style object.
(function () {
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_CLASS = { critical: 'st-fail', high: 'st-fail', medium: 'st-warn', low: '', info: '' };
  const ST_CLASS = { open: 'st-fail', fixed: 'st-ok', accepted: '' };
  const PART = { tests: 'tests', findings: 'findings', coverage: 'standards coverage' };
  const num = v => (typeof v === 'number' && isFinite(v) ? v : null);
  const fmt = v => (num(v) == null ? '—' : String(Math.round(v * 10) / 10));
  const arr = v => (Array.isArray(v) ? v : []);
  const obj = v => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  const chip = (text, cls) => `<span class="df-chip ${E(cls || '')}">${E(text)}</span>`;
  const pct = v => Math.max(0, Math.min(100, num(v) || 0));

  function noScore(reason) {
    $('advQsBox').innerHTML = `<div class="adv-sbd-score"><div class="n">—</div><div class="g">No score yet</div></div>
      <div class="adv-qs-meaning">${E(reason || 'No score yet: the score file is not there.')}</div>`;
    $('advQsBody').hidden = true;
  }

  function renderBox(d) {
    const o = obj(d.overall);
    const cap = o.cap && typeof o.cap === 'object' ? o.cap : null;
    const score = num(o.score);
    const capLine = cap ? `<div class="adv-qs-cap">${E(cap.applied ? `Capped at ${cap.limit}: ` : `Cap in force (${cap.limit}): `)}${E(cap.reason)}</div>` : '';
    if (score == null) {
      $('advQsBox').innerHTML = `<div class="adv-sbd-score"><div class="n">—</div><div class="g">No score yet</div></div>
        <div class="adv-qs-meaning">${E(o.meaning || 'No full test run is recorded yet.')} The standards coverage and the findings below are already current.</div>${capLine}`;
      return;
    }
    $('advQsBox').innerHTML = `<div class="adv-sbd-score"><div class="n">${E(score)}<span class="pct">/100</span></div><div class="g">Grade ${E(o.grade)} · ${E(o.label)}</div></div>
      <div class="adv-qs-meaning">${E(o.meaning)}</div>${capLine}`;
  }

  function renderChart(areas) {
    const el = $('advQsChart');
    const rows = [];
    for (const a of areas) {
      rows.push({ cls: 'area', name: a.name, score: a.score });
      const subs = arr(a.subs);
      if (subs.length > 1) for (const s of subs) rows.push({ cls: 'sub', name: s.name, score: s.score });
    }
    if (!rows.some(r => num(r.score) != null)) {
      el.innerHTML = '<p class="dim">The chart appears once a full test run is recorded.</p>';
      return;
    }
    el.innerHTML = rows.map(r => `<div class="adv-qs-row ${E(r.cls)}"><span class="adv-qs-name">${E(r.name)}</span>
      <span class="adv-qs-track"><span class="adv-qs-fill"></span></span><span class="adv-qs-val">${E(fmt(r.score))}</span></div>`).join('');
    el.querySelectorAll('.adv-qs-fill').forEach((f, i) => { f.style.width = pct(rows[i].score) + '%'; });
  }

  function summary(d, areas) {
    const o = obj(d.overall);
    if (num(o.score) == null) return 'No overall score yet, because no full test run is recorded. The table lists each area\'s standards coverage and findings.';
    const subs = areas.flatMap(a => arr(a.subs).map(s => ({ n: s.name, v: num(s.score) }))).filter(s => s.v != null);
    const low = subs.sort((x, y) => x.v - y.v)[0];
    return `Overall ${o.score} of 100 (grade ${o.grade}, ${o.label}). By area: ${areas.map(a => `${a.name} ${fmt(a.score)}`).join(', ')}.`
      + (low ? ` The lowest part is ${low.n} at ${fmt(low.v)}.` : '');
  }

  function renderAreas(areas) {
    const rows = [];
    for (const a of areas) {
      const subs = arr(a.subs);
      for (const s of subs) {
        const t = s.tests && typeof s.tests === 'object' ? s.tests : null;
        const f = s.findings && typeof s.findings === 'object' ? s.findings : null;
        const c = obj(s.coverage);
        const nCov = arr(c.covered).length, nAll = nCov + arr(c.missing).length;
        const name = subs.length > 1 ? `${a.name}: ${s.name}` : a.name;
        const miss = arr(c.missing).length ? ` <span class="dim">Missing: ${arr(c.missing).map(E).join(', ')}</span>` : '';
        rows.push(`<tr><th scope="row">${E(name)}</th><td><strong>${E(fmt(s.score))}</strong></td>
          <td>${t ? `${E(fmt(t.score))}% <span class="dim">(${E(t.passed)} passed, ${E(t.failed)} failed)</span>` : '<span class="dim">no run</span>'}</td>
          <td>${f ? E(f.open) : '<span class="dim">no record</span>'}</td>
          <td>${E(nCov)} of ${E(nAll)}${miss}</td>
          <td>${arr(s.based_on).map(k => E(PART[k] || k)).join(', ') || '<span class="dim">—</span>'}</td></tr>`);
      }
    }
    $('advQsAreas').querySelector('tbody').innerHTML = rows.join('');
  }

  function renderCounts(d) {
    const by = obj(obj(d.counts).by_severity);
    $('advQsCounts').querySelector('tbody').innerHTML = SEV.map(s => {
      const b = obj(by[s]);
      return `<tr><th scope="row">${chip(s, SEV_CLASS[s])}</th><td>${E(b.open || 0)}</td><td>${E(b.fixed || 0)}</td><td>${E(b.accepted || 0)}</td></tr>`;
    }).join('');
  }

  function renderOpen(d, areas) {
    const names = {};
    for (const a of areas) for (const s of arr(a.subs)) names[s.key] = arr(a.subs).length > 1 ? `${a.name}: ${s.name}` : a.name;
    const open = arr(d.findings).filter(f => f && f.status === 'open');
    const none = $('advQsOpenNone'), table = $('advQsOpen');
    if (!open.length) {
      none.hidden = false;
      none.textContent = arr(d.findings).length ? 'No finding is open: every recorded finding is fixed or accepted.' : 'No findings are recorded yet, so none is open.';
      table.parentElement.hidden = true;
      return;
    }
    none.hidden = true;
    table.parentElement.hidden = false;
    table.querySelector('tbody').innerHTML = open.map(f => `<tr><th scope="row"><code>${E(f.id)}</code> ${E(f.title)}</th>
      <td>${chip(f.severity, SEV_CLASS[f.severity])}</td>
      <td>${E([f.cwe, f.asvs || f.wcag].filter(Boolean).join(' · ') || '—')}</td>
      <td>${E(names[f.sub_area] || 'Other')}</td>
      <td>${E(f.reason || f.fix || '—')}</td></tr>`).join('');
  }

  function renderStandards(d) {
    const st = obj(d.standards);
    const groups = [
      ['OWASP ASVS 4.0.3 chapters', arr(st.asvs_chapters)], ['WCAG 2.2 AA', arr(st.wcag)], ['OWASP Top 10 2021', arr(st.top10)],
      ['SLSA v1.0', arr(st.slsa)], ['OpenSSF Scorecard', arr(st.scorecard)], ['NIST SSDF', arr(st.ssdf)],
    ];
    const cwe = arr(st.cwe).length;
    $('advQsStd').innerHTML = groups.map(([label, ids]) => `<p class="adv-lead"><strong>${E(label)}</strong> (${E(ids.length)}): ${ids.length ? ids.map(i => chip(i)).join(' ') : '<span class="dim">none yet</span>'}</p>`).join('')
      + `<p class="adv-lead"><strong>CWE</strong>: ${E(cwe)} weaknesses have a test. The full list is in the report.</p>`;
  }

  function renderRun(d) {
    const r = d.run && typeof d.run === 'object' ? d.run : null;
    $('advQsRun').textContent = r
      ? `Test run: commit ${r.commit}, ${r.date}. ${r.passed} passed, ${r.failed} failed, ${r.errors || 0} errors, ${r.skipped} skipped, ${r.duration_s} s.`
      : 'No full test run is recorded yet (docs/qa/test_run.json).';
  }

  function render(d) {
    d = obj(d);
    if (!d.available) { noScore(d.reason); return; }
    const areas = arr(d.areas).filter(a => a && typeof a === 'object');
    renderBox(d);
    renderChart(areas);
    $('advQsText').textContent = summary(d, areas);
    renderAreas(areas);
    renderCounts(d);
    renderOpen(d, areas);
    renderStandards(d);
    renderRun(d);
    $('advQsBody').hidden = false;
  }

  async function load() {
    $('advQsBox').innerHTML = '<span class="dim">Loading the score…</span>';
    try {
      const r = await fetch('/api/quality-score', { cache: 'no-store' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d && d.detail) || `Error ${r.status}`);
      render(d);
    } catch (e) {
      noScore(`No score yet: the score could not be loaded (${e.message}).`);
    }
  }

  window.DLP_QS = { render };
  if ($('advQsBox')) {
    $('advQsReload').addEventListener('click', load);
    load();
  }
})();
