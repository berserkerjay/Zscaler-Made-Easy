// ── Evaluate All Rules: how ZIA decides, and a simulator for ties ─────
// Rendered into #evalAllFlow inside the Inline DLP Rule Migration modal.
// Pure DOM, no tenant call: the simulator runs on rules typed here, on
// the presets, or on the rules Step 2 downloaded.
//
// What ZIA does (Zscaler: "About First Match Wins and Evaluate All Rules
// for DLP", help.zscaler.com/zia/about-first-match-wins-and-evaluate-all-rules-for-dlp):
//   Rule Order (first match wins): rules are walked by order; the first
//     rule whose criteria match decides, and nothing below it is looked at.
//   Evaluate All Rules: every enabled rule is evaluated; among the rules
//     that match, the most restrictive action wins (Block, then Isolate,
//     then Confirm, then Allow); when several matching rules carry that
//     same action the one with the highest priority (lowest order number)
//     is the one applied, and its notification template, auditor,
//     Incident Receiver / ICAP and severity settings are used.
const EA_RANK = { BLOCK: 0, ISOLATE: 1, CONFIRM: 2, CAUTION: 2, ALLOW: 3, ALERT: 3, MONITOR: 3, ICAP_RESPONSE: 3 };
const EA_LABEL = { BLOCK: 'Block', ISOLATE: 'Isolate', CONFIRM: 'Confirm (justification)', CAUTION: 'Caution', ALLOW: 'Allow (monitor)', ALERT: 'Alert', MONITOR: 'Monitor', ICAP_RESPONSE: 'Allow (ICAP)' };
const EA_SOURCE = 'https://help.zscaler.com/zia/about-first-match-wins-and-evaluate-all-rules-for-dlp';
const _eaE = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const EA_PRESETS = {
  tie: {
    label: 'Tie: two Block rules match',
    match: 'Credit Cards, US SSN',
    rules: [
      { name: 'Monitor everything', order: 1, action: 'ALLOW', engines: '', enabled: true },
      { name: 'Block PCI to file sharing', order: 2, action: 'BLOCK', engines: 'Credit Cards', enabled: true, template: 'PCI auditor template', receiver: true },
      { name: 'Block PII to GenAI', order: 3, action: 'BLOCK', engines: 'US SSN', enabled: true, template: '', receiver: false },
      { name: 'Confirm HR data', order: 4, action: 'CONFIRM', engines: 'US SSN', enabled: true },
    ],
  },
  shadow: {
    label: 'Monitor rule above a Block rule',
    match: 'Credit Cards',
    rules: [
      { name: 'Monitor everything', order: 1, action: 'ALLOW', engines: '', enabled: true },
      { name: 'Block PCI', order: 2, action: 'BLOCK', engines: 'Credit Cards', enabled: true, template: 'PCI auditor template', receiver: true },
    ],
  },
  confirm: {
    label: 'Confirm vs Allow, no Block',
    match: 'Source Code',
    rules: [
      { name: 'Allow engineering repos', order: 1, action: 'ALLOW', engines: 'Source Code', enabled: true },
      { name: 'Confirm code to GenAI', order: 2, action: 'CONFIRM', engines: 'Source Code', enabled: true, template: 'Code template' },
      { name: 'Disabled block', order: 3, action: 'BLOCK', engines: 'Source Code', enabled: false },
    ],
  },
};
let EA_RULES = JSON.parse(JSON.stringify(EA_PRESETS.tie.rules));

function _eaSplit(s) { return String(s || '').split(',').map(x => x.trim()).filter(Boolean); }
function _eaAct(a) { return String(a || 'ALLOW').toUpperCase().replace(/[^A-Z_]/g, ''); }

// The decision, as data: every step ZIA takes, in order.
function evalAllSimulate(rules, matchEngines) {
  const want = new Set(_eaSplit(matchEngines).map(x => x.toLowerCase()));
  const enabled = rules.filter(r => r.enabled !== false);
  const byOrder = [...enabled].sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0));
  const matching = byOrder.filter(r => {
    const eng = _eaSplit(r.engines);
    return eng.length === 0 || eng.some(e => want.has(e.toLowerCase()));
  });
  const steps = [];
  steps.push({ n: 1, title: 'Every enabled rule is evaluated', text: `${enabled.length} enabled rule(s) (${rules.length - enabled.length} disabled skipped). Order never stops the evaluation in this mode.` });
  steps.push({ n: 2, title: 'Rules whose criteria match this transaction', text: matching.length ? matching.map(r => `${r.name} (order ${r.order}, ${EA_LABEL[_eaAct(r.action)] || r.action})`).join('; ') : 'none: the transaction is allowed by default and no DLP log line is written.', rules: matching.map(r => r.name) });
  if (!matching.length) return { steps, winner: null, matching, firstMatch: null, tie: false };
  const best = Math.min(...matching.map(r => EA_RANK[_eaAct(r.action)] ?? 3));
  const bestAct = matching.filter(r => (EA_RANK[_eaAct(r.action)] ?? 3) === best);
  const actName = EA_LABEL[_eaAct(bestAct[0].action)] || bestAct[0].action;
  steps.push({ n: 3, title: 'The most restrictive action wins', text: `Actions among the matches: ${[...new Set(matching.map(r => EA_LABEL[_eaAct(r.action)] || r.action))].join(', ')} → ${actName} (Block > Isolate > Confirm > Allow).`, action: actName });
  const tie = bestAct.length > 1;
  const winner = bestAct[0]; // already sorted by order: lowest order number = highest priority
  if (tie) {
    steps.push({ n: 4, title: 'Tie on the action: rule order breaks it', text: `${bestAct.length} rules carry ${actName}: ${bestAct.map(r => `${r.name} (order ${r.order})`).join(', ')}. The rule with the highest priority, i.e. the lowest order number, is applied: ${winner.name} (order ${winner.order}).`, tie: true, candidates: bestAct.map(r => r.name) });
  } else {
    steps.push({ n: 4, title: 'No tie', text: `Only ${winner.name} carries ${actName}, so it is the rule applied.` });
  }
  steps.push({ n: 5, title: 'The winning rule\'s settings apply', text: `${winner.name} decides the action (${actName})${winner.template ? `, sends the ${winner.template}` : ', sends no notification template'}${winner.receiver ? ', forwards the match to the Incident Receiver' : ''}${winner.severity ? `, severity ${winner.severity}` : ''}. Its rule name, engines and dictionary counts are what the DLP log line and the Workflow Automation incident carry.` });
  const firstMatch = matching[0];
  if (firstMatch && firstMatch !== winner) {
    steps.push({ n: 6, title: 'What Rule Order (first match wins) would have done', text: `${firstMatch.name} (order ${firstMatch.order}) is the first match, so in Rule Order mode the transaction would have been ${EA_LABEL[_eaAct(firstMatch.action)] || firstMatch.action} and ${winner.name} would never have run: that is the shadowing Evaluate All Rules removes.`, shadow: true });
  } else if (firstMatch) {
    steps.push({ n: 6, title: 'Rule Order would agree', text: `${firstMatch.name} is also the first match by order, so both modes give the same result here.` });
  }
  return { steps, winner, matching, firstMatch, tie, action: actName };
}

function _eaRulesHtml() {
  const opts = a => ['BLOCK', 'ISOLATE', 'CONFIRM', 'ALLOW'].map(k => `<option value="${k}" ${_eaAct(a) === k ? 'selected' : ''}>${EA_LABEL[k]}</option>`).join('');
  return `<table class="ea-table" aria-label="Rules in the simulation"><thead><tr><th>On</th><th>Rule</th><th>Order</th><th>Action</th><th>Engines (comma-separated; empty = any content)</th><th>Template</th><th>Incident Receiver</th><th></th></tr></thead><tbody>
    ${EA_RULES.map((r, i) => `<tr>
      <td><input type="checkbox" aria-label="Rule ${_eaE(r.name)} enabled" ${r.enabled !== false ? 'checked' : ''} onchange="_eaSet(${i},'enabled',this.checked)"></td>
      <td><input type="text" aria-label="Rule name" value="${_eaE(r.name)}" onchange="_eaSet(${i},'name',this.value)"></td>
      <td><input type="number" aria-label="Order" min="1" value="${Number(r.order) || 1}" style="width:4.5rem" onchange="_eaSet(${i},'order',Number(this.value))"></td>
      <td><select aria-label="Action" onchange="_eaSet(${i},'action',this.value)">${opts(r.action)}</select></td>
      <td><input type="text" aria-label="Engines" value="${_eaE(r.engines)}" onchange="_eaSet(${i},'engines',this.value)"></td>
      <td><input type="text" aria-label="Notification template" value="${_eaE(r.template || '')}" placeholder="none" onchange="_eaSet(${i},'template',this.value)"></td>
      <td><input type="checkbox" aria-label="Forwards to the Incident Receiver" ${r.receiver ? 'checked' : ''} onchange="_eaSet(${i},'receiver',this.checked)"></td>
      <td><button type="button" class="btn btn-ghost" style="padding:0.2rem 0.5rem;font-size:0.75rem;" aria-label="Remove rule ${_eaE(r.name)}" onclick="_eaRemove(${i})">✕</button></td>
    </tr>`).join('')}
  </tbody></table>`;
}
function _eaSet(i, k, v) { if (EA_RULES[i]) { EA_RULES[i][k] = v; _eaRun(); } }
function _eaRemove(i) { EA_RULES.splice(i, 1); _eaRender(); }
function _eaAdd() { EA_RULES.push({ name: `Rule ${EA_RULES.length + 1}`, order: EA_RULES.length + 1, action: 'BLOCK', engines: '', enabled: true }); _eaRender(); }
function _eaPreset(k) {
  const p = EA_PRESETS[k]; if (!p) return;
  EA_RULES = JSON.parse(JSON.stringify(p.rules));
  const m = document.getElementById('eaMatch'); if (m) m.value = p.match;
  _eaRender();
}
// Step 2 of the wizard hands its downloaded rules here.
function evalAllLoadRules(rules) {
  if (!Array.isArray(rules) || !rules.length) return;
  EA_RULES = rules.slice(0, 60).map(r => ({
    name: r.name || `rule ${r.id}`, order: r.order || 0, action: _eaAct(typeof r.action === 'object' ? (r.action && r.action.type) : r.action),
    engines: ((r.dlpEngines || r.dlp_engines || []).map(e => (e && e.name) || e).filter(Boolean)).join(', '),
    enabled: String(r.state || 'ENABLED').toUpperCase() === 'ENABLED',
    template: (r.notificationTemplate && r.notificationTemplate.name) || '', receiver: !!(r.zscalerIncidentReceiver || r.icapServer), severity: r.severity || '',
  }));
  const b = document.getElementById('eaLoaded'); if (b) b.textContent = `${EA_RULES.length} rule(s) loaded from Step 2.`;
  _eaRender();
}
window.evalAllLoadRules = evalAllLoadRules;

function _eaRun() {
  const out = document.getElementById('eaResult'); if (!out) return;
  const res = evalAllSimulate(EA_RULES, (document.getElementById('eaMatch') || {}).value || '');
  out.innerHTML = `<ol class="ea-steps">${res.steps.map(s => `<li class="${s.tie ? 'tie' : ''} ${s.shadow ? 'shadow' : ''}"><strong>${_eaE(s.title)}</strong><div>${_eaE(s.text)}</div></li>`).join('')}</ol>
    <div class="ea-verdict ${res.winner ? 'has' : ''}" role="status">${res.winner ? `Result: <strong>${_eaE(res.action)}</strong> by <strong>${_eaE(res.winner.name)}</strong> (order ${_eaE(res.winner.order)})${res.tie ? ' — decided on order, because more than one rule carried that action' : ''}.` : 'Result: no rule matches; allowed by default.'}</div>`;
}

function _eaRender() {
  const host = document.getElementById('evalAllFlow'); if (!host) return;
  const match = (document.getElementById('eaMatch') || {}).value || EA_PRESETS.tie.match;
  host.innerHTML = `
  <details class="ea-wrap" open>
    <summary><span style="font-size:0.7rem;color:var(--accent);font-weight:700;letter-spacing:0.1em;">HOW IT WORKS</span> <strong>Evaluate All Rules: how ZIA decides, and what happens on a tie</strong></summary>
    <div class="ea-flow" role="list" aria-label="Decision flow">
      <div class="ea-lane" role="listitem"><div class="ea-lane-t">Rule Order (first match wins)</div>
        <div class="ea-box">Transaction</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Walk rules by order</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box warn">First rule that matches decides</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box dim">Everything below is never looked at</div>
      </div>
      <div class="ea-lane" role="listitem"><div class="ea-lane-t">Evaluate All Rules</div>
        <div class="ea-box">Transaction</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Every enabled rule evaluated</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Matching set</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box ok">Most restrictive action wins<br><span class="ea-sub">Block › Isolate › Confirm › Allow</span></div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box tie">Tie on the action?<br><span class="ea-sub">lowest order number wins</span></div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Winner's template, auditor, Incident Receiver, severity apply</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box dim">DLP log → Incident Receiver → Workflow Automation</div>
      </div>
    </div>
    <p class="ea-note">Source: Zscaler, <a href="${EA_SOURCE}" target="_blank" rel="noopener noreferrer">About First Match Wins and Evaluate All Rules for DLP</a>. Rule order still matters in Evaluate All Rules: it is the tie-breaker among rules that carry the same action, and the winning rule is the one whose notification and incident settings are used.</p>
    <div class="ea-sim">
      <div class="ea-sim-h"><strong>Simulate a transaction</strong>
        <span class="ea-presets">${Object.entries(EA_PRESETS).map(([k, p]) => `<button type="button" class="btn btn-ghost" style="padding:0.3rem 0.7rem;font-size:0.76rem;" onclick="_eaPreset('${k}')">${_eaE(p.label)}</button>`).join('')}<button type="button" class="btn btn-ghost" style="padding:0.3rem 0.7rem;font-size:0.76rem;" onclick="_eaAdd()">+ Add rule</button><span id="eaLoaded" class="ea-note" style="margin:0;"></span></span>
      </div>
      ${_eaRulesHtml()}
      <label class="ea-match">Engines the transaction matches (comma-separated) <input id="eaMatch" type="text" value="${_eaE(match)}" oninput="_eaRun()"></label>
      <div id="eaResult" aria-live="polite"></div>
    </div>
  </details>`;
  _eaRun();
}

(function () {
  const style = document.createElement('style');
  style.textContent = `
  .ea-wrap { margin: 0 0 0.9rem; padding: 0.75rem 1rem; background: var(--well); border: 1px solid var(--border); border-radius: 10px; }
  .ea-wrap > summary { cursor: pointer; font-size: 0.95rem; }
  .ea-flow { display: flex; flex-direction: column; gap: 0.6rem; margin: 0.8rem 0 0.4rem; }
  .ea-lane { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; padding: 0.55rem 0.7rem; border: 1px dashed var(--border); border-radius: 8px; }
  .ea-lane-t { flex-basis: 100%; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--dim); }
  .ea-box { padding: 0.45rem 0.65rem; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); font-size: 0.8rem; line-height: 1.3; }
  .ea-box.ok { border-color: var(--pass); } .ea-box.warn { border-color: var(--warn); } .ea-box.tie { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, transparent); } .ea-box.dim { color: var(--dim); }
  .ea-sub { font-size: 0.72rem; color: var(--dim); }
  .ea-arrow { color: var(--dim); }
  .ea-note { font-size: 0.78rem; color: var(--dim); margin: 0.4rem 0 0.6rem; }
  .ea-sim { border-top: 1px solid var(--border); padding-top: 0.6rem; }
  .ea-sim-h { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
  .ea-presets { display: flex; gap: 0.35rem; flex-wrap: wrap; align-items: center; }
  .ea-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .ea-table th { text-align: left; font-size: 0.66rem; letter-spacing: 0.06em; text-transform: uppercase; color: var(--dim); padding: 0.3rem 0.4rem; }
  .ea-table td { padding: 0.25rem 0.4rem; border-top: 1px solid var(--border); }
  .ea-table input[type=text], .ea-table input[type=number], .ea-table select { width: 100%; padding: 0.3rem 0.45rem; font-size: 0.8rem; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; }
  .ea-match { display: block; margin: 0.6rem 0; font-size: 0.82rem; } .ea-match input { display: block; width: 100%; margin-top: 0.25rem; padding: 0.4rem 0.6rem; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; }
  .ea-steps { margin: 0.4rem 0 0 1.2rem; font-size: 0.82rem; } .ea-steps li { margin-bottom: 0.35rem; } .ea-steps li div { color: var(--dim); }
  .ea-steps li.tie { padding: 0.3rem 0.5rem; background: color-mix(in srgb, var(--accent) 12%, transparent); border-radius: 6px; } .ea-steps li.tie div { color: var(--text); }
  .ea-steps li.shadow { border-left: 3px solid var(--warn); padding-left: 0.5rem; }
  .ea-verdict { margin-top: 0.5rem; padding: 0.5rem 0.7rem; border-radius: 8px; border: 1px solid var(--border); font-size: 0.85rem; } .ea-verdict.has { border-color: var(--accent); }`;
  document.head.appendChild(style);
  const boot = () => _eaRender();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
window.evalAllSimulate = evalAllSimulate;
