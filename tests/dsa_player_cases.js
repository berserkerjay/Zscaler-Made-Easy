'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const registry = require('../static/reference/dsa_flows.js');
const P = require('../static/reference/dsa_player.js');
const expected = require('./dsa_expected_inventory.json');
const source = fs.readFileSync(path.join(root, 'static/reference/data-security-architect.html'), 'utf8');
const code = fs.readFileSync(path.join(root, 'static/reference/dsa_player.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'static/reference/dsa_player.css'), 'utf8');
const cases = [];
function test(id, scope, assertion, run) { cases.push({ id, scope, assertion, run }); }
function clock() {
  let id = 0, time = 0; const active = new Map(), all = new Map(), delays = [];
  return { active, all, delays, now() { return time; }, advance(ms) { time += ms; }, schedule(fn, ms) { active.set(++id, fn); all.set(id, fn); delays.push(ms); return id; }, cancel(i) { active.delete(i); }, tick() { const next = active.entries().next().value; if (!next) return false; active.delete(next[0]); next[1](); return true; }, drain() { let n = 0; while (this.tick()) assert.ok(++n < 100); return n; } };
}
function controller(flow, options = {}) { const c = clock(), p = P.createController(flow, { schedule: c.schedule.bind(c), cancel: c.cancel.bind(c), now: c.now.bind(c), ...options }); return { c, p }; }
function body(id) { const start = source.indexOf('id="dsa-' + id + '"'); return source.slice(start, source.indexOf(id.startsWith('setup') || id.startsWith('walkback') ? '</details>' : '</figure>', start)); }
const keywords = {
 'chains-1': ['match counts', 'Boolean', 'Incident Receiver', 'NSS', 'metadata'],
 'chains-2': ['confidence', 'four engines', 'Channels'],
 'chains-3': ['ZIR', 'cloud-to-cloud', 'storage event', 'metadata', 'NSS'],
 'dictionary-1': ['Patterns & Phrases', 'EDM', 'IDM', 'MIP', 'count'],
 'dictionary-2': ['OCR', 'Match Type', 'proximity', 'equal to N'],
 'dictionary-5': ['false positives', 'strict format', '256', 'proximity'],
 'dictionary-3': ['primary', 'Secondary Match On', 'required-but-blank'],
 'dictionary-4': ['25%', '50%', '75%', 'Exclude 100%'],
 'engine-1': ['Exclude cannot', 'four subexpressions', 'sixteen', 'two count', 'nothing may nest'],
 'engine-2': ['4 and 2', 'false at 3', 'every', 'at least one', 'more than 6'],
 'engine-3': ['mandatory', 'Only selected channels', 'active policy'],
 'access': ['SSL', 'Cloud App Control', 'URL Filtering', 'File Type Control', 'Dictionary', 'Engine', 'Workflow Automation'],
 'channels-1': ['URL Filtering', 'SSL', 'File Type Control', 'AND', 'OR', 'fails open', 'dictionary', 'Engine'],
 'endpoint': ['local cache', 'Device Control', 'on-device', 'most restrictive', 'evidence'],
 'channels-2': ['offline', '12-hour', 'ALL', 'on-device', 'most restrictive', 'connectivity'],
 'email': ['Smart host', 'tenant', 'recipient', 'headers', 'not platform enforcement', 'transport rules'],
 'channels-3': ['per recipient', 'Block beats Quarantine', 'Exchange-only', 'platform', 'evidence'],
 'saas': ['quarantine', 'started', 'cutoff', 'per-file', 'DSPM'],
 'sspm': ['scopes', 'posture', 'third-party', 'separate from content DLP'],
 'edmidm-1': ['shapes', 'records', 'overlap', 'match count', 'Boolean'],
 'edmidm-2': ['hashes', 'Completed', 'dictionaries', 'Channels', 'pre-filter', 'separately'],
 'edmidm-3': ['primary', 'Secondary fields alone', 'all mandatory', 'optional', 'deleting existing'],
 'aisec': ['Endpoint', 'SSL', 'URL Filtering', 'File Type Control', 'ZIA dictionary', 'proxy-chain', 'own prompt', 'response', 'no NSS or WA'],
 'workflow-1': ['cloud-to-cloud', 'ZIR', 'cloud buckets', 'storage events', 'Validate', 'metadata'],
 'workflow-2': ['Received', 'Investigating', 'Validating with User', 'Received Justification Response', 'Escalated', 'Resolved', 'Reopen', 'irreversible'],
 'workflow-3': ['published', 'survey', 'branch', 'ticket', 'one Close', 'never escalate after Close'],
 'workflow-4': ['rule', 'application', 'severity', 'queue', 'resolution', 'tuning'],
 'workflow-5': ['reminders', 'justification', 'resolution', 'separate escalation'],
 'workflow-6': ['Received Justification Response', 'SCIM', 'CSV', 'manager', 'ticket'],
 'workflow-7': ['inline web or email', 'outside the DLP admin', 'per-user subrule', 'time-limited'],
 'workflow-8': ['Exchange Online', 'transport rule', 'evidence', 'analyst', 'delete'],
 'workflow-9': ['business unit', 'region', 'source', 'default group', 'assigned groups'],
 'workflow-10': ['obfuscated', 'severity', 'cannot drive group', 'justified escalation', 'prevents quarantine release']
};
function unescape(s) { return s.replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'"); }
expected.forEach(function (e) {
 const f = registry.byId[e.id];
 test('COV-DOM-' + e.id, 'per-flow animation', 'Exact original ' + e.kind + ' remains bound once to ' + e.title, () => {
   assert.ok(f); assert.equal((source.match(new RegExp('data-dsa-flow="' + e.id + '"', 'g')) || []).length, 1);
   assert.equal(f.title, e.title); assert.equal(f.section, e.section); assert.equal(f.kind, e.kind);
   if (e.kind === 'figure') { assert.ok(body(e.id).includes('class="zoom"')); assert.ok(body(e.id).includes(f.image)); assert.ok(fs.existsSync(path.join(root, f.image))); assert.ok(body(e.id).includes('<figcaption>')); }
   else { assert.ok(body(e.id).includes('<summary>')); assert.ok(body(e.id).includes('<ol>')); }
 });
 test('COV-SEMANTICS-' + e.id, 'per-flow animation', 'Required reference decisions and their order survive in ' + e.title, () => {
   assert.deepEqual(f.stages.map(s => s.id), e.stages); assert.equal(new Set(e.stages).size, e.stages.length);
   assert.deepEqual(f.stages.map(s => s.label), e.stageLabels);
   const text = JSON.stringify(f).toLowerCase();
   if (e.kind === 'figure') keywords[e.id].forEach(k => assert.ok(text.includes(k.toLowerCase()), e.id + ' missing ' + k));
   else {
     const rows = [...body(e.id).matchAll(/<li[^>]*>(.*?)<\/li>/gs)].map(m => unescape(m[1].replace(/<[^>]+>/g, '')).trim());
     assert.deepEqual(f.stages.map(s => s.detail), rows);
   }
 });
 test('PLAY-' + e.id, 'Play All / Guided Next', 'Play All visits the complete ordered ' + e.title + ' path and cancels on completion', () => {
   const seen = [], { c, p } = controller(f, { render: s => seen.push(s.cursor) });
   p.dispatch({ type: 'PLAY' }); assert.equal(p.getState().cursor, 0); assert.equal(c.active.size, 1);
   c.drain(); assert.deepEqual(seen, f.stages.map((_, i) => i)); assert.equal(p.getState().status, 'complete'); assert.equal(c.active.size, 0);
   assert.deepEqual(P.stageStates(f, p.getState()), f.stages.map(() => 'completed'));
 });
 test('GUIDED-' + e.id, 'Play All / Guided Next', 'Guided Next advances exactly one explanatory stage for ' + e.title + ' without timers', () => {
   const { c, p } = controller(f); p.dispatch({ type: 'GUIDED' });
   for (let i = 0; i < f.stages.length; ++i) {
     assert.equal(p.getState().cursor, i); assert.equal(c.active.size, 0);
     assert.equal(P.stageStates(f, p.getState())[i], i === f.stages.length - 1 ? 'completed' : 'active');
     p.dispatch({ type: 'NEXT' });
   }
   assert.equal(p.getState().status, 'complete'); assert.equal(p.getState().cursor, f.stages.length - 1);
 });
 f.scenarios.filter(s => Number.isInteger(s.stopAt)).forEach(s => {
   test('STOP-' + e.id + '-' + s.id, 'Play All / Guided Next', s.label + ': stop the sample at ' + f.stages[s.stopAt].label + ' and never animate downstream stages', () => {
     const { c, p } = controller(f); p.dispatch({ type: 'SCENARIO', value: s.id }); p.dispatch({ type: 'PLAY' }); c.drain();
     assert.equal(p.getState().status, 'stopped'); assert.equal(p.getState().cursor, e.stops[s.id]);
     assert.equal(c.active.size, 0); const before = p.getState(); p.dispatch({ type: 'NEXT' }); assert.equal(p.getState(), before);
     assert.deepEqual(P.stageStates(f, before).slice(s.stopAt + 1), f.stages.slice(s.stopAt + 1).map(() => 'not_reached'));
   });
 });
});
const semanticChecks = [
 ['upstream-order', 'access', f => assert.deepEqual(f.stages.slice(1,6).map(s=>s.id), ['ssl_tls_inspection','cloud_app_control','url_filtering','threat_checks','file_type_control'])],
 ['inline-detection-order','channels-1',f=>assert.ok(f.stages.findIndex(s=>s.id==='dictionary_matching') < f.stages.findIndex(s=>s.id==='engine_inspection'))],
 ['endpoint-device-before-dlp','endpoint',f=>assert.ok(f.stages.findIndex(s=>s.id==='device_control') < f.stages.findIndex(s=>s.id==='dictionary_inspection'))],
 ['email-platform-enforcement','email',f=>assert.ok(f.stages.findIndex(s=>s.id==='verdict_headers') < f.stages.findIndex(s=>s.id==='platform_enforcement'))],
 ['evidence-not-nss','chains-3',f=>assert.match(f.stages.at(-1).detail,/NSS.*parallel outputs/)],
 ['strict-greater-than','engine-2',f=>assert.match(f.stages.find(s=>s.id==='sum_operator').detail,/6 does not satisfy more than 6/)],
 ['sspm-not-dlp','sspm',f=>assert.match(f.note,/separate from content DLP/)],
 ['dspm-not-inline','saas',f=>assert.match(f.note,/DSPM.*separate assessments, not inline enforcement/)],
 ['ai-telemetry-boundary','aisec',f=>assert.match(f.stages.at(-1).detail,/no NSS or WA integration/)],
 ['ai-file-passthrough','aisec',f=>assert.match(f.stages.find(s=>s.id==='ai_guard_response_detectors').detail,/files pass through without documented file inspection/)],
 ['endpoint-idm-special-case','edmidm-2',f=>assert.match(f.stages.at(-1).detail,/separately built endpoint index/)],
 ['anchor-secondaries-insufficient','edmidm-3',f=>assert.match(f.stages[1].detail,/alone never trigger/)],
 ['idM-exclusion-stop','dictionary-4',f=>assert.equal(f.scenarios[1].stopAt,2)],
 ['ocr-stop-before-count','dictionary-2',f=>assert.ok(f.scenarios[1].stopAt < f.stages.findIndex(s=>s.id==='dictionary_count'))],
 ['primary-before-secondary','dictionary-3',f=>assert.deepEqual(f.stages.slice(1,3).map(s=>s.id),['primary_match','secondary_match'])],
 ['template-before-dictionary','edmidm-2',f=>assert.equal(f.stages[1].id,'completed_template')],
 ['scan-start-before-inspection','saas',f=>assert.ok(f.scenarios[1].stopAt < f.stages.findIndex(s=>s.id==='dictionary_and_engine'))],
 ['response-before-escalation','workflow-6',f=>assert.equal(f.stages[0].id,'justification_response')],
 ['manager-import-gate','workflow-6',f=>assert.equal(f.scenarios[2].stopAt,1)],
 ['publish-before-actions','workflow-3',f=>assert.equal(f.scenarios[1].stopAt,0)],
 ['exchange-only-release','workflow-8',f=>assert.equal(f.scenarios[1].stopAt,0)],
 ['inline-email-only-exception','workflow-7',f=>assert.match(f.stages[0].detail,/inline web or email/)],
 ['obfuscated-recipient-limit','workflow-10',f=>assert.match(f.stages.at(-1).detail,/obfuscated recipient prevents quarantine release/)],
 ['onprem-no-wa','workflow-1',f=>assert.match(f.scenarios[1].note,/does not supply the required cloud event lane/)],
 ['privacy-no-identity-read','workflow-10',f=>assert.match(f.stages.at(-1).detail,/does not expose identity/)],
 ['monitor-only-not-zero-telemetry','channels-2',f=>assert.match(f.scenarios[1].note,/not proof that telemetry ceases/)]
];
semanticChecks.forEach(([id, flowId, check])=>test('COV-DOMAIN-'+id,'per-flow animation',id.replace(/-/g,' '),()=>check(registry.byId[flowId])));
test('COV-total-coverage','per-flow animation','Exactly 33 original figures, 6 setups and 5 diagnostic walkbacks are covered',()=>{
 assert.equal(registry.flows.length,44); assert.equal(registry.flows.filter(f=>f.kind==='figure').length,33); assert.equal(registry.flows.filter(f=>f.kind==='setup').length,6); assert.equal(registry.flows.filter(f=>f.kind==='walkback').length,5);
 assert.equal(new Set(registry.flows.map(f=>f.id)).size,44);
});
test('COV-preserve-lightbox','per-flow animation','Original full-size / fit / close lightbox behavior remains wired',()=>['dlg.showModal()','mode(\'fit\')','dlg.close()','last.focus()'].forEach(x=>assert.ok(source.includes(x))));
test('COV-zero-tenant-access','per-flow animation','Registry/player cannot send tenant traffic or modify shared animation state',()=>{
 assert.doesNotMatch(code,/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage)\b/); assert.doesNotMatch(code,/\bFA\./);
 assert.ok(source.includes('Nothing here reads a tenant')); assert.ok(source.includes('2026-09-29'));
});
test('COV-web-applicability','per-flow animation','Only inline web and the AI inline branch claim web-prerequisite applicability',()=>assert.deepEqual(registry.flows.filter(f=>f.web).map(f=>f.id),['access','channels-1','aisec','setup-inline','walkback-inline']));
test('COV-motion-and-print','per-flow animation','CSS removes motion under reduced-motion preference and exposes state in print',()=>{ assert.match(css,/@media\(prefers-reduced-motion:reduce\)/); assert.match(css,/animation:none!important/); assert.match(css,/@media print/); });
const f=registry.byId.access;
const interactions = [
 ['pause-cancels-timer',({p,c})=>{p.dispatch({type:'PLAY'});p.dispatch({type:'PAUSE'});assert.equal(c.active.size,0);assert.equal(p.getState().cursor,0);}],
 ['resume-preserves-cursor',({p,c})=>{p.dispatch({type:'PLAY'});c.tick();p.dispatch({type:'PAUSE'});p.dispatch({type:'RESUME'});c.tick();assert.equal(p.getState().cursor,2);}],
 ['stale-tick-after-pause',({p,c})=>{p.dispatch({type:'PLAY'});const stale=[...c.all.values()][0];p.dispatch({type:'PAUSE'});stale();assert.equal(p.getState().cursor,0);assert.equal(c.active.size,0);}],
 ['stale-tick-after-restart',({p,c})=>{p.dispatch({type:'PLAY'});const stale=[...c.all.values()][0];p.dispatch({type:'RESTART'});stale();assert.equal(p.getState().cursor,-1);assert.equal(c.active.size,0);}],
 ['stale-tick-after-new-play',({p,c})=>{p.dispatch({type:'PLAY'});const stale=[...c.all.values()][0];p.dispatch({type:'PLAY'});stale();assert.equal(p.getState().cursor,0);assert.equal(c.active.size,1);}],
 ['guided-switch-cancels-auto',({p,c})=>{p.dispatch({type:'PLAY'});c.tick();p.dispatch({type:'GUIDED'});assert.equal(p.getState().cursor,0);assert.equal(c.active.size,0);}],
 ['next-switch-cancels-auto',({p,c})=>{p.dispatch({type:'PLAY'});p.dispatch({type:'NEXT'});assert.equal(p.getState().cursor,1);assert.equal(p.getState().mode,'guided');assert.equal(c.active.size,0);}],
 ['back-pauses-and-rewinds',({p,c})=>{p.dispatch({type:'PLAY'});c.tick();p.dispatch({type:'BACK'});assert.equal(p.getState().cursor,0);assert.equal(p.getState().status,'paused');assert.equal(c.active.size,0);}],
 ['back-at-start-bounded',({p,c})=>{p.dispatch({type:'GUIDED'});p.dispatch({type:'BACK'});assert.equal(p.getState().cursor,0);assert.equal(c.active.size,0);}],
 ['restart-retains-scenario-speed',({p})=>{p.dispatch({type:'SCENARIO',value:'stop_1'});p.dispatch({type:'SPEED',value:2});p.dispatch({type:'PLAY'});p.dispatch({type:'RESTART'});assert.equal(p.getState().scenarioId,'stop_1');assert.equal(p.getState().speed,2);assert.equal(p.getState().cursor,-1);}],
 ['replay-rearms-one-timer',({p,c})=>{p.dispatch({type:'PLAY'});c.tick();p.dispatch({type:'REPLAY'});assert.equal(p.getState().cursor,1);assert.equal(p.getState().replay,1);assert.equal(c.active.size,1);}],
 ['replay-guided-no-timer',({p,c})=>{p.dispatch({type:'GUIDED'});p.dispatch({type:'REPLAY'});assert.equal(p.getState().replay,1);assert.equal(c.active.size,0);}],
 ['speed-reschedules-duration',({p,c})=>{p.dispatch({type:'PLAY'});p.dispatch({type:'SPEED',value:2});assert.equal(c.delays.at(-1),1100);assert.equal(c.active.size,1);}],
 ['slow-speed-duration',({p,c})=>{p.dispatch({type:'SPEED',value:0.5});p.dispatch({type:'PLAY'});assert.equal(c.delays.at(-1),4400);}],
 ['invalid-speed-rejected',({p})=>{const before=p.getState();p.dispatch({type:'SPEED',value:0});assert.equal(p.getState(),before);p.dispatch({type:'SPEED',value:NaN});assert.equal(p.getState(),before);}],
 ['scenario-change-cancels',({p,c})=>{p.dispatch({type:'PLAY'});const old=[...c.all.values()][0];p.dispatch({type:'SCENARIO',value:'stop_2'});old();assert.equal(p.getState().cursor,-1);assert.equal(c.active.size,0);}],
 ['unknown-scenario-rejected',({p})=>{const before=p.getState();p.dispatch({type:'SCENARIO',value:'invalid'});assert.equal(p.getState(),before);}],
 ['reduce-motion-pauses',({p,c})=>{p.dispatch({type:'PLAY'});p.dispatch({type:'MOTION',value:true});assert.equal(p.getState().status,'paused');assert.equal(p.getState().reducedMotion,true);assert.equal(c.active.size,0);}],
 ['reduced-play-still-completes',({p,c})=>{p.dispatch({type:'MOTION',value:true});p.dispatch({type:'PLAY'});c.drain();assert.equal(p.getState().status,'complete');assert.equal(p.getState().reducedMotion,true);}],
 ['destroy-cancels-and-rejects',({p,c})=>{p.dispatch({type:'PLAY'});const old=[...c.all.values()][0];p.destroy();const before=p.getState();old();p.dispatch({type:'NEXT'});assert.equal(p.getState(),before);assert.equal(c.active.size,0);}],
 ['back-from-complete-reopens',({p,c})=>{p.dispatch({type:'PLAY'});c.drain();p.dispatch({type:'BACK'});assert.equal(p.getState().status,'paused');assert.equal(p.getState().cursor,f.stages.length-2);}],
 ['stop-back-rechecks-gate',({p,c})=>{p.dispatch({type:'SCENARIO',value:'stop_1'});p.dispatch({type:'PLAY'});c.drain();p.dispatch({type:'BACK'});assert.equal(p.getState().cursor,2);p.dispatch({type:'NEXT'});assert.equal(p.getState().status,'stopped');}],
 ['restart-clears-visual-states',({p,c})=>{p.dispatch({type:'PLAY'});c.tick();p.dispatch({type:'RESTART'});assert.ok(P.stageStates(f,p.getState()).every(s=>s==='pending'));}],
 ['immutable-reducer-input',({p})=>{const state=Object.freeze(p.getState());const next=P.reduce(f,state,{type:'PLAY'});assert.equal(state.cursor,-1);assert.equal(next.cursor,0);}],
 ['unknown-action-noop',({p})=>{const s=p.getState();p.dispatch({type:'NOOP'});assert.equal(p.getState(),s);}],
 ['controls-terminal-disabled',({p,c})=>{p.dispatch({type:'PLAY'});c.drain();assert.deepEqual(P.controls(f,p.getState()),{back:true,next:false,replay:true,pause:false,resume:false,restart:true});}]];
interactions.forEach(([id,check])=>test('INT-'+id,'Play All / Guided Next',id.replace(/-/g,' '),()=>check(controller(f))));
['ArrowRight','ArrowLeft','Home','r',' ','Escape'].forEach((key,i)=>test('KEY-'+i,'Play All / Guided Next','Panel keyboard mapping for '+JSON.stringify(key),()=>assert.equal(P.keyboardAction(key,P.initial(f),'SECTION')?.type||null,['NEXT','BACK','RESTART','REPLAY','PLAY',null][i])));
test('KEY-ignore-form-controls','Play All / Guided Next','Keyboard shortcuts do not hijack speed, scenario, links or buttons',()=>['INPUT','SELECT','TEXTAREA','BUTTON','A'].forEach(tag=>assert.equal(P.keyboardAction('ArrowRight',P.initial(f),tag),null)));
test('KEY-ignore-editable','Play All / Guided Next','Editable text is excluded from player shortcuts',()=>assert.equal(P.keyboardAction(' ',P.initial(f),'DIV',true),null));
// Minimal deterministic DOM fixture: tests component wiring, not a browser renderer.
class Node {
 constructor(tag){this.tagName=tag.toUpperCase();this.children=[];this.attributes={};this.dataset={};this.listeners={};this.style={setProperty:(k,v)=>{this.style[k]=v;}};this.textContent='';this.className='';this.open=true;}
 appendChild(n){this.children.push(n);n.parentNode=this;return n;}
 removeChild(n){this.children.splice(this.children.indexOf(n),1);return n;}
 insertBefore(n,target){const i=this.children.indexOf(target);if(i<0)return this.appendChild(n);this.children.splice(i,0,n);n.parentNode=this;return n;}
 setAttribute(k,v){this.attributes[k]=String(v);} removeAttribute(k){delete this.attributes[k];}
 addEventListener(k,fn){(this.listeners[k] ||= []).push(fn);} removeEventListener(k,fn){this.listeners[k]=(this.listeners[k]||[]).filter(x=>x!==fn);}
 emit(k,event={}){(this.listeners[k]||[]).forEach(fn=>fn({...event,target:event.target||this}));}
 querySelector(s){return this.querySelectorAll(s)[0]||null;}
 querySelectorAll(s){const a=[];function match(n){if(s[0]==='.')return n.className.split(' ').includes(s.slice(1));const m=s.match(/^\[data-([^=]+)="([^"]+)"\]$/);if(m)return n.dataset[m[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]===m[2];return n.tagName===s.toUpperCase();}function walk(n){n.children.forEach(c=>{if(match(c))a.push(c);walk(c);});}walk(this);return a;}
}
function fixture(){const doc=new Node('document');doc.createElement=t=>new Node(t);doc.createTextNode=t=>{const n=new Node('#text');n.textContent=t;return n;};registry.flows.forEach(f=>{const h=new Node(f.kind==='figure'?'figure':'details');h.dataset.dsaFlow=f.id;h.appendChild(new Node(f.kind==='figure'?'figcaption':'ol'));doc.appendChild(h);});const c=clock(),win=new Node('window'),media=new Node('media');media.matches=false;win.matchMedia=()=>media;win.performance={now:c.now.bind(c)};win.setTimeout=c.schedule.bind(c);win.clearTimeout=c.cancel.bind(c);return {doc,c,win,media,players:P.mountAll(doc,registry,win)};}
expected.forEach(e=>test('DOM-PLAYER-'+e.id,'per-flow animation','Accessible independent player mounts for '+e.title,()=>{
 const x=fixture(),player=x.players.find(p=>p.shell.dataset.flowId===e.id);assert.ok(player);assert.equal(player.shell.querySelectorAll('button').length,8);assert.equal(player.shell.querySelectorAll('.dsa-timeline')[0].children.length,e.stages.length);assert.equal(player.shell.querySelector('.dsa-status').attributes['aria-live'],'polite');assert.equal(player.shell.tabIndex,0);assert.equal(player.shell.querySelectorAll('select').length,2);assert.equal(player.shell.querySelector('.dsa-gates').children.length,3);x.players.destroy();
}));
test('DOM-single-active-player','Play All / Guided Next','Starting a second flow pauses the first and keeps one timer',()=>{const x=fixture();x.players[0].shell.querySelector('[data-action="PLAY"]').emit('click');x.players[1].shell.querySelector('[data-action="PLAY"]').emit('click');assert.equal(x.players[0].controller.getState().status,'paused');assert.equal(x.players[1].controller.getState().status,'playing');assert.equal(x.c.active.size,1);x.players.destroy();});
test('DOM-hidden-tab-pauses','Play All / Guided Next','A hidden page cancels pending auto playback',()=>{const x=fixture();x.players[0].controller.dispatch({type:'PLAY'});x.doc.hidden=true;x.doc.emit('visibilitychange');assert.equal(x.c.active.size,0);assert.equal(x.players[0].controller.getState().status,'paused');x.players.destroy();});
test('DOM-pagehide-pauses','Play All / Guided Next','Navigation cancels auto playback without a surprise resume',()=>{const x=fixture();x.players[0].controller.dispatch({type:'PLAY'});x.win.emit('pagehide');assert.equal(x.c.active.size,0);x.players.destroy();});
test('DOM-collapse-pauses','Play All / Guided Next','Collapsing an open setup stops its playback timer',()=>{const x=fixture();const p=x.players.find(p=>p.shell.dataset.flowId==='setup-inline');p.controller.dispatch({type:'PLAY'});p.host.open=false;p.host.emit('toggle');assert.equal(p.controller.getState().status,'paused');assert.equal(x.c.active.size,0);x.players.destroy();});
test('DOM-os-motion-change','Play All / Guided Next','OS motion preference changes pause active playback and update every checkbox',()=>{const x=fixture();x.players[0].controller.dispatch({type:'PLAY'});x.media.emit('change',{matches:true});assert.equal(x.c.active.size,0);assert.ok(x.players.every(p=>p.controller.getState().reducedMotion));x.players.destroy();});
test('DOM-no-duplicate-mount','per-flow animation','Repeated boot does not duplicate a flow player',()=>{const x=fixture();assert.equal(P.mountAll(x.doc,registry,x.win).length,0);assert.equal(x.doc.querySelectorAll('.dsa-player').length,44);x.players.destroy();});
test('DOM-render-stop-labels','Play All / Guided Next','Stop scenario selector renders not-reached text and disables Next',()=>{const x=fixture();const p=x.players.find(p=>p.shell.dataset.flowId==='access');const select=p.shell.querySelectorAll('select')[1];select.value='stop_1';select.emit('change');p.shell.querySelector('[data-action="PLAY"]').emit('click');x.c.drain();assert.ok(p.shell.querySelector('[data-action="NEXT"]').disabled);const nodes=p.shell.querySelector('.dsa-timeline').children;assert.equal(nodes[3].dataset.state,'stopped');assert.ok(nodes.slice(4).every(n=>n.dataset.state==='not_reached'));x.players.destroy();});
test('DOM-destroy-detaches','Play All / Guided Next','Destroy cancels timers and detaches page lifecycle listeners',()=>{const x=fixture();x.players[0].controller.dispatch({type:'PLAY'});x.players.destroy();assert.equal(x.c.active.size,0);assert.equal(x.doc.listeners.visibilitychange.length,0);assert.equal(x.win.listeners.pagehide.length,0);assert.equal(x.media.listeners.change.length,0);});

test('INT-pause-preserves-elapsed','Play All / Guided Next','Pause at 900ms and resume with exactly 1300ms left in the same stage',()=>{const {p,c}=controller(f);p.dispatch({type:'PLAY'});c.advance(900);p.dispatch({type:'PAUSE'});assert.equal(p.getState().remainingMs,1300);c.advance(6000);p.dispatch({type:'RESUME'});assert.equal(c.delays.at(-1),1300);assert.equal(p.getState().cursor,0);});
test('INT-speed-preserves-progress','Play All / Guided Next','Speed change preserves completed stage fraction and rescales only remaining duration',()=>{const {p,c}=controller(f);p.dispatch({type:'PLAY'});c.advance(1000);p.dispatch({type:'SPEED',value:2});assert.equal(p.getState().remainingMs,1200);assert.equal(c.delays.at(-1),600);c.advance(100);p.dispatch({type:'PAUSE'});assert.equal(p.getState().remainingMs,1000);});
test('INT-next-double-click-guard','Play All / Guided Next','Rapid duplicate Next is ignored during transition; later deliberate Next advances',()=>{const c=clock(),p=P.createController(f,{schedule:c.schedule.bind(c),cancel:c.cancel.bind(c),now:c.now.bind(c),nextThrottleMs:250});p.dispatch({type:'GUIDED'});p.dispatch({type:'NEXT'});p.dispatch({type:'NEXT'});assert.equal(p.getState().cursor,1);c.advance(251);p.dispatch({type:'NEXT'});assert.equal(p.getState().cursor,2);assert.equal(c.active.size,0);});
test('DOM-directed-connected-graph','per-flow animation','Every noninitial stage has a directed connector and animation packet',()=>{const x=fixture();x.players.forEach(p=>{const nodes=p.shell.querySelector('.dsa-timeline').children;assert.equal(nodes[0].querySelector('.dsa-connector'),null);nodes.slice(1).forEach(n=>{assert.ok(n.querySelector('.dsa-connector'));assert.ok(n.querySelector('.dsa-packet'));});});assert.match(css,/border-left:7px solid/);assert.match(css,/@keyframes dsa-travel/);x.players.destroy();});
test('DOM-guided-travel-and-replay','Play All / Guided Next','Guided Next creates an animated arrival packet; Replay replaces it without changing the stage',()=>{const x=fixture(),p=x.players[0];p.shell.querySelector('[data-action="GUIDED"]').emit('click');p.shell.querySelector('[data-action="NEXT"]').emit('click');const stage=p.shell.querySelector('.dsa-timeline').children[1],old=stage.querySelector('.dsa-packet');assert.ok(old.className.includes('dsa-arrival'));p.shell.querySelector('[data-action="REPLAY"]').emit('click');assert.notEqual(stage.querySelector('.dsa-packet'),old);assert.equal(p.controller.getState().cursor,1);assert.equal(x.c.active.size,0);x.players.destroy();});
test('DOM-progress-freeze-render','Play All / Guided Next','Paused rendering preserves fractional progress; resume recreates remaining animation',()=>{const x=fixture(),p=x.players[0];p.shell.querySelector('[data-action="PLAY"]').emit('click');x.c.advance(1100);p.shell.querySelector('[data-action="PAUSE"]').emit('click');assert.equal(p.shell.style['--dsa-progress'],'0.5');assert.equal(p.shell.style['--dsa-duration'],'1100ms');const old=p.shell.querySelector('.dsa-progress-bar');p.shell.querySelector('[data-action="RESUME"]').emit('click');assert.notEqual(p.shell.querySelector('.dsa-progress-bar'),old);assert.equal(x.c.delays.at(-1),1100);x.players.destroy();});


test('DOM-first-stage-replay-cue','Play All / Guided Next','First-stage Guided and Replay animate the node even without an incoming edge',()=>{const x=fixture(),p=x.players[0];p.shell.querySelector('[data-action="GUIDED"]').emit('click');const old=p.shell.querySelector('.dsa-stage-number');assert.ok(old.className.includes('dsa-node-arrival'));p.shell.querySelector('[data-action="REPLAY"]').emit('click');assert.notEqual(p.shell.querySelector('.dsa-stage-number'),old);assert.equal(p.controller.getState().cursor,0);x.players.destroy();});

if (process.argv.includes('--list')) process.stdout.write(JSON.stringify(cases.map(({id,scope,assertion})=>({id,scope,assertion}))));
else {
 const results=cases.map(({id,scope,assertion,run})=>{try{run();return {id,scope,assertion,status:'passed'};}catch(e){return {id,scope,assertion,status:'failed',error:e.stack};}});
 process.stdout.write(JSON.stringify({summary:{total:results.length,passed:results.filter(x=>x.status==='passed').length,failed:results.filter(x=>x.status==='failed').length,browser:'not run: supported browser launch blocked; no bypass attempted'},cases:results},null,2));
 if(results.some(r=>r.status==='failed'))process.exitCode=1;
}
