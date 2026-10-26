// ── Evaluate All Rules: how ZIA decides ───────────────────────────────
// Rendered into #evalAllFlow inside the Inline DLP rule migration modal
// and on the /report/evalall reference tab. Pure DOM, no tenant call.
//
// What ZIA does (Zscaler: "Configuring DLP Policy Rules with Evaluate All
// Rules Mode Enabled", help.zscaler.com/zia/configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled.
// It replaced "About First Match Wins and Evaluate All Rules for DLP",
// which the help center no longer has; the Isolate step and the channel
// list below come from that older article):
//   Rule Order (first match wins): rules are walked by order; the first
//     rule whose criteria match decides, and nothing below it is looked at.
//   Evaluate All Rules: every enabled rule is evaluated; among the rules
//     that match, the most restrictive action wins (Block, then Isolate,
//     then Confirm, then Allow); when several matching rules carry that
//     same action the one with the highest priority (lowest order number)
//     is the one applied, and its notification template, auditor,
//     Incident Receiver / ICAP and severity settings are used.
// Which channels evaluate every rule: Inline Web DLP (once the Advanced
// Settings switch is on), Endpoint DLP and Outbound Email DLP. SaaS
// Security API DLP rules are the exception: they are walked in order per
// rule type and the first match decides, so no tie is possible there.
const EA_SOURCE = 'https://help.zscaler.com/zia/configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled';

function _eaRender() {
  const host = document.getElementById('evalAllFlow'); if (!host) return;
  host.innerHTML = `
  <details class="ea-wrap" open>
    <summary><span style="font-size:0.7rem;color:var(--accent);font-weight:700;letter-spacing:0.1em;">HOW IT WORKS</span> <strong>Evaluate All Rules: how ZIA decides, and what happens on a tie</strong> ${location.pathname === '/report/evalall' ? '' : '<a href="/report/evalall" target="_blank" rel="noopener" style="margin-left:0.6rem;font-size:0.8rem;font-weight:400;">Open the decision diagram in its own tab ↗</a>'}</summary>
    <div class="ea-flow" role="list" aria-label="Decision flow">
      <div class="ea-lane" role="listitem"><div class="ea-lane-t">Rule Order (first match wins) — SaaS Security API DLP rules, per rule type; also Inline Web DLP before the switch</div>
        <div class="ea-box">Transaction</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Walk rules by order</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box warn">First rule that matches decides<br><span class="ea-sub">No tie-breaker on this channel: a stricter rule further down is shadowed until it is moved up</span></div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box dim">Everything below is never looked at</div>
      </div>
      <div class="ea-lane" role="listitem"><div class="ea-lane-t">Evaluate All Rules — Inline Web DLP (once switched on), Endpoint DLP, Outbound Email DLP</div>
        <div class="ea-box">Transaction</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Every enabled rule evaluated</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Matching set</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box ok">Most restrictive action wins<br><span class="ea-sub">Block › Isolate › Confirm › Allow</span></div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box tie">Tie on the action?<br><span class="ea-sub">Rule order breaks the tie: the lowest order number wins</span></div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box">Winner's template, auditor, Incident Receiver, severity apply</div><div class="ea-arrow" aria-hidden="true">→</div>
        <div class="ea-box dim">DLP log → Incident Receiver → Workflow Automation</div>
      </div>
    </div>
    <p class="ea-note">Source: Zscaler, <a href="${EA_SOURCE}" target="_blank" rel="noopener noreferrer">Configuring DLP Policy Rules with Evaluate All Rules Mode Enabled</a>. <strong>Channels:</strong> Inline Web DLP (with the Advanced Settings switch on), Endpoint DLP and Outbound Email DLP evaluate all rules; SaaS Security API DLP rules are the exception, walked in order per rule type with the first match deciding. Rule order still matters in Evaluate All Rules: it is the tie-breaker among rules that carry the same action, and the winning rule is the one whose notification and incident settings are used. A Monitor (Allow) rule placed above a Block rule shadows it only in Rule Order mode; Evaluate All Rules removes that shadowing.</p>
  </details>`;
}

(function () {
  const style = document.createElement('style');
  style.textContent = `
  .ea-wrap { margin: 0 0 0.9rem; padding: 0.75rem 1rem; background: var(--well); border: 1px solid var(--border); border-radius: var(--r-md); }
  .ea-wrap > summary { cursor: pointer; font-size: 0.95rem; }
  .ea-flow { display: flex; flex-direction: column; gap: 0.6rem; margin: 0.8rem 0 0.4rem; }
  .ea-lane { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; padding: 0.55rem 0.7rem; border: 1px dashed var(--border); border-radius: 8px; }
  .ea-lane-t { flex-basis: 100%; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--dim); }
  .ea-box { padding: 0.45rem 0.65rem; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); font-size: 0.8rem; line-height: 1.3; }
  .ea-box.ok { border-color: var(--pass); } .ea-box.warn { border-color: var(--warn); } .ea-box.tie { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, transparent); } .ea-box.dim { color: var(--dim); }
  .ea-sub { font-size: 0.72rem; color: var(--dim); }
  .ea-arrow { color: var(--dim); }
  .ea-note { font-size: 0.78rem; color: var(--dim); margin: 0.4rem 0 0.6rem; }`;
  document.head.appendChild(style);
  const boot = () => _eaRender();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
