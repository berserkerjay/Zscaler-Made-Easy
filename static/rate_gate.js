// The rate-limit check before anything is written to or deleted from ZIA.
// Every deploy, removal, migration post or delete, remediation and proposal
// asks /api/rate-check first (nothing is sent to ZIA by that call) and shows
// the answer in the confirmation: the verdict (sarcastic when Zscaler's API
// limits are being crushed), the API plan, and the tenant's track record.
'use strict';

// The check as plain text for a confirmation dialog.
function zdRateText(f) {
  if (!f) return 'Rate-limit check: not available. ZIA may still refuse requests for its rate.';
  const when = f.run_after ? ` (${new Date(f.run_after * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} your time)` : '';
  const plan = (f.plan || []).map(l => `  • ${l}`).join('\n');
  return `Rate-limit check: ${f.title}\n${f.verdict}${when}` + (plan ? `\n\nAPI plan:\n${plan}` : '') + (f.success ? `\n\n${f.success.text}` : '');
}

// Ask the server how `counts` ({write, delete, endpoint_rules, cloud_app,
// activate}) meet ZIA's limits for the tenant in `creds`, show it with
// `action` in a confirmation, and resolve to true only on OK.
async function zdRateGate(counts, creds, action) {
  let f = null;
  try {
    const r = await fetch('/api/rate-check', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                               body: JSON.stringify({ ...(creds || {}), counts: counts || {} }) });
    if (r.ok) f = await r.json();
  } catch (e) { f = null; }
  let ok = false;
  try { ok = window.confirm(`${zdRateText(f)}\n\n${action || 'Send these changes to ZIA?'}\n\nClick OK to go ahead, or Cancel to stop.`); } catch (e) { ok = false; }
  return ok;
}

window.zdRateText = zdRateText;
window.zdRateGate = zdRateGate;
