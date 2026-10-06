/* Deterministic lifecycle and child-handshake cases. These test real
 * production controllers with fake time/DOM, not browser rendering. */
const assert = require('node:assert/strict');
const api = require('../../static/reference/reference_embeds.js');
const child = require('../../static/reference/reference_embed_child.js');
const cases = [];
function add(name, run) { cases.push({name,run}); }
function fixture(slug, opts={}) {
  let serial=0, now=0;
  const timers=new Map(), changes=[], frame={contentWindow:{},src:''};
  const controller=api.createController({slug, frame, origin:'http://localhost:8001',
    tokenFactory:()=> 'load-'+(++serial),
    setTimeout:(fn,ms)=>{const id=++now;timers.set(id,{fn,ms});return id;},
    clearTimeout:id=>timers.delete(id), onChange:s=>changes.push(s), ...opts});
  const event = (overrides={}, outer={}) => ({origin:'http://localhost:8001',source:frame.contentWindow,
    data:{type:'dlp-reference-state',slug,token:controller.snapshot().token,state:'ready',...overrides},...outer});
  const ready=()=>controller.receive(event());
  const timeout=()=>{const jobs=Array.from(timers.values());timers.clear();jobs.forEach(t=>t.fn());};
  return {controller,frame,timers,changes,event,ready,timeout};
}
function childFixture(slug, opts={}) {
  const sent=[], listeners={}, domListeners={};
  const doc={readyState:'loading',
    querySelector:s=>s==='meta[name="dlp-reference-embed"]'?{content:slug}:{},
    getElementById:id=>id==='matrix'?{children:[{},{}]}:{},
    addEventListener:(name,fn)=>domListeners[name]=fn};
  const win={document:doc, location:{href:'http://localhost:8001/reference/embed/'+slug+'?embed_token=t1',origin:'http://localhost:8001'},
    parent:{postMessage:(data,origin)=>sent.push({data,origin})},
    addEventListener:(name,fn)=>listeners[name]=fn,
    __mapShow:()=>{},switchTab:()=>{},renderMatrix:()=>{}};
  Object.assign(win,opts);return {win,doc,sent,listeners,domListeners};
}
for (const slug of Object.keys(api.definitions)) {
  const test=(name,fn)=>add(slug+'/'+name,()=>fn(slug));
  test('initial-state-idle',s=>assert.equal(fixture(s).controller.snapshot().state,'idle'));
  test('lazy-no-navigation',s=>assert.equal(fixture(s).frame.src,''));
  test('explicit-open-enters-loading',s=>{const f=fixture(s);assert.equal(f.controller.load(),true);assert.equal(f.controller.snapshot().state,'loading');});
  test('fixed-same-origin-route',s=>{const f=fixture(s);f.controller.load();const u=new URL(f.frame.src);assert.equal(u.origin,'http://localhost:8001');assert.equal(u.pathname,'/reference/embed/'+s);});
  test('navigation-token-attached',s=>{const f=fixture(s);f.controller.load();assert.equal(new URL(f.frame.src).searchParams.get('embed_token'),f.controller.snapshot().token);});
  test('token-query-encoding',s=>{const f=fixture(s,{tokenFactory:()=>'<&=?#'});f.controller.load();assert.equal(new URL(f.frame.src).searchParams.get('embed_token'),'<&=?#');assert.ok(!f.frame.src.includes('<'));});
  test('timeout-is-bounded',s=>{const f=fixture(s);f.controller.load();assert.equal([...f.timers.values()][0].ms,15000);});
  test('one-loading-notification',s=>{const f=fixture(s);f.controller.load();assert.deepEqual(f.changes.map(x=>x.state),['loading']);});
  test('repeated-open-does-not-navigate',s=>{const f=fixture(s);f.controller.load();const first=f.frame.src;assert.equal(f.controller.load(),false);assert.equal(f.frame.src,first);});
  test('repeated-open-keeps-one-timer',s=>{const f=fixture(s);f.controller.load();f.controller.load();assert.equal(f.timers.size,1);});
  test('only-valid-ready-unlocks',s=>{const f=fixture(s);f.controller.load();assert.equal(f.ready(),true);assert.equal(f.controller.snapshot().state,'ready');});
  test('ready-cancels-timeout',s=>{const f=fixture(s);f.controller.load();f.ready();assert.equal(f.timers.size,0);});
  test('ready-tab-revisit-preserves-navigation',s=>{const f=fixture(s);f.controller.load();f.ready();const first=f.frame.src;assert.equal(f.controller.load(),false);assert.equal(f.frame.src,first);});
  test('duplicate-ready-is-ignored',s=>{const f=fixture(s);f.controller.load();f.ready();assert.equal(f.ready(),false);assert.equal(f.changes.length,2);});
  test('timeout-shows-error',s=>{const f=fixture(s);f.controller.load();f.timeout();assert.equal(f.controller.snapshot().state,'error');});
  test('error-not-permanent-loaded-flag',s=>{const f=fixture(s);f.controller.load();f.timeout();assert.equal(f.controller.load(),true);assert.equal(f.controller.snapshot().state,'loading');});
  test('retry-uses-fresh-token',s=>{const f=fixture(s);f.controller.load();const t=f.controller.snapshot().token;f.controller.fail(t);f.controller.load(true);assert.notEqual(f.controller.snapshot().token,t);});
  test('retry-cancels-previous-deadline',s=>{const f=fixture(s);f.controller.load();f.controller.load(true);assert.equal(f.timers.size,1);assert.equal(f.controller.snapshot().generation,2);});
  test('stale-timeout-cannot-break-retry',s=>{const f=fixture(s);f.controller.load();const timer=[...f.timers.values()][0];f.controller.load(true);timer.fn();assert.equal(f.controller.snapshot().state,'loading');});
  test('stale-ready-cannot-complete-retry',s=>{const f=fixture(s);f.controller.load();const evt=f.event();f.controller.load(true);assert.equal(f.controller.receive(evt),false);assert.equal(f.controller.snapshot().state,'loading');});
  test('stale-error-cannot-break-retry',s=>{const f=fixture(s);f.controller.load();const evt=f.event({state:'error'});f.controller.load(true);assert.equal(f.controller.receive(evt),false);});
  test('ready-after-timeout-does-not-hide-error',s=>{const f=fixture(s);f.controller.load();f.timeout();assert.equal(f.ready(),false);assert.equal(f.controller.snapshot().state,'error');});
  test('explicit-retry-can-complete',s=>{const f=fixture(s);f.controller.load();f.timeout();f.controller.load(true);assert.equal(f.ready(),true);});
  test('child-error-during-loading',s=>{const f=fixture(s);f.controller.load();assert.equal(f.controller.receive(f.event({state:'error'})),true);assert.equal(f.controller.snapshot().state,'error');});
  test('runtime-error-after-ready',s=>{const f=fixture(s);f.controller.load();f.ready();f.controller.receive(f.event({state:'error'}));assert.equal(f.controller.snapshot().state,'error');});
  test('duplicate-error-not-reannounced',s=>{const f=fixture(s);f.controller.load();f.controller.receive(f.event({state:'error'}));assert.equal(f.controller.receive(f.event({state:'error'})),false);assert.equal(f.changes.length,2);});
  test('force-reload-ready-document',s=>{const f=fixture(s);f.controller.load();f.ready();assert.equal(f.controller.load(true),true);assert.equal(f.controller.snapshot().generation,2);});
  test('late-ready-from-prior-ready-document',s=>{const f=fixture(s);f.controller.load();f.ready();const evt=f.event();f.controller.load(true);assert.equal(f.controller.receive(evt),false);});
  const rejected=[
    ['missing-event',()=>null],['missing-data',f=>f.event({}, {data:null})],
    ['string-data',f=>f.event({}, {data:'ready'})],['array-data',f=>f.event({}, {data:[]})],
    ['wrong-message-type',f=>f.event({type:'ready'})],['wrong-slug',f=>f.event({slug:'another-reference'})],
    ['missing-token',f=>f.event({token:null})],['wrong-token',f=>f.event({token:'attacker'})],
    ['wrong-parent-origin',f=>f.event({}, {origin:'https://example.com'})],
    ['wrong-app-port',f=>f.event({}, {origin:'http://localhost:8002'})],
    ['null-origin',f=>f.event({}, {origin:'null'})],['sibling-frame-source',f=>f.event({}, {source:{}})],
    ['null-source',f=>f.event({}, {source:null})],['unknown-state',f=>f.event({state:'loaded'})]
  ];
  for(const [name,make] of rejected)test('reject-'+name,s=>{const f=fixture(s);f.controller.load();assert.equal(f.controller.receive(make(f)),false);assert.equal(f.controller.snapshot().state,'loading');assert.equal(f.timers.size,1);});
  test('ready-before-first-load-rejected',s=>{const f=fixture(s);assert.equal(f.ready(),false);assert.equal(f.controller.snapshot().state,'idle');});
  test('wrong-failure-token-rejected',s=>{const f=fixture(s);f.controller.load();assert.equal(f.controller.fail('wrong'),false);assert.equal(f.controller.snapshot().state,'loading');});
  test('destroy-cancels-timeout',s=>{const f=fixture(s);f.controller.load();f.controller.destroy();assert.equal(f.timers.size,0);});
  test('destroy-clears-navigation-token',s=>{const f=fixture(s);f.controller.load();f.controller.destroy();assert.equal(f.controller.snapshot().token,null);});
  test('destroyed-controller-cannot-open',s=>{const f=fixture(s);f.controller.destroy();assert.equal(f.controller.load(true),false);assert.equal(f.frame.src,'');});
  test('destroyed-controller-ignores-ready',s=>{const f=fixture(s);f.controller.load();const evt=f.event();f.controller.destroy();assert.equal(f.controller.receive(evt),false);});
  test('destroyed-controller-ignores-error',s=>{const f=fixture(s);f.controller.load();const evt=f.event({state:'error'});f.controller.destroy();assert.equal(f.controller.receive(evt),false);});
  test('destroy-is-idempotent',s=>{const f=fixture(s);f.controller.destroy();f.controller.destroy();assert.equal(f.changes.length,1);});
  test('old-timeout-after-destroy-is-harmless',s=>{const f=fixture(s);f.controller.load();const job=[...f.timers.values()][0];f.controller.destroy();job.fn();assert.equal(f.controller.snapshot().state,'destroyed');});
  test('navigation-exception-becomes-retryable-error',s=>{const frame={contentWindow:{},set src(x){throw Error('navigation failed')}};const f=fixture(s,{frame});f.controller.load();assert.equal(f.controller.snapshot().state,'error');assert.equal(f.timers.size,0);});
  test('snapshot-is-immutable',s=>{const f=fixture(s);assert.ok(Object.isFrozen(f.controller.snapshot()));});
  test('https-origin-supported',s=>{const f=fixture(s,{origin:'https://example.test'});f.controller.load();assert.equal(new URL(f.frame.src).origin,'https://example.test');});
  test('opaque-origin-rejected',s=>assert.throws(()=>fixture(s,{origin:'data:text/html,hello'}),/HTTP/));
  test('child-waits-for-dom-content',s=>{const f=childFixture(s);child.start(f.win);assert.equal(f.sent.length,0);assert.equal(typeof f.domListeners.DOMContentLoaded,'function');});
  test('child-ready-message-contract',s=>{const f=childFixture(s);child.start(f.win);f.domListeners.DOMContentLoaded();assert.deepEqual(f.sent,[{origin:f.win.location.origin,data:{type:'dlp-reference-state',slug:s,token:'t1',state:'ready'}}]);});
  test('child-already-parsed-document',s=>{const f=childFixture(s);f.doc.readyState='complete';child.start(f.win);assert.equal(f.sent[0].data.state,'ready');});
  test('child-script-error-before-dom',s=>{const f=childFixture(s);child.start(f.win);f.listeners.error({target:f.win,error:Error('syntax')});f.domListeners.DOMContentLoaded();assert.deepEqual(f.sent.map(x=>x.data.state),['error']);});
  test('child-script-resource-failure',s=>{const f=childFixture(s);child.start(f.win);f.listeners.error({target:{tagName:'SCRIPT'}});assert.equal(f.sent[0].data.state,'error');});
  test('child-image-error-is-not-page-failure',s=>{const f=childFixture(s);child.start(f.win);f.listeners.error({target:{tagName:'IMG'}});f.domListeners.DOMContentLoaded();assert.equal(f.sent[0].data.state,'ready');});
  test('child-font-style-error-is-not-page-failure',s=>{const f=childFixture(s);child.start(f.win);f.listeners.error({target:{tagName:'LINK'}});assert.equal(f.sent.length,0);});
  test('child-unhandled-promise-error',s=>{const f=childFixture(s);child.start(f.win);f.listeners.unhandledrejection({target:f.win});assert.equal(f.sent[0].data.state,'error');});
  test('child-runtime-error-after-ready',s=>{const f=childFixture(s);child.start(f.win);f.domListeners.DOMContentLoaded();f.listeners.error({target:f.win,error:Error('runtime')});assert.deepEqual(f.sent.map(x=>x.data.state),['ready','error']);});
  test('child-duplicate-error-suppressed',s=>{const f=childFixture(s);const bridge=child.start(f.win);bridge.error({target:f.win});bridge.error({target:f.win});assert.equal(f.sent.length,1);});
  test('child-no-token-sends-nothing',s=>{const f=childFixture(s);f.win.location.href='http://localhost:8001/reference/embed/'+s;assert.equal(child.start(f.win),null);assert.equal(f.sent.length,0);});
  test('child-standalone-no-parent-message',s=>{const f=childFixture(s);f.win.parent=f.win;assert.equal(child.start(f.win),null);});
  test('child-unrecognized-metadata-rejected',s=>{const f=childFixture(s);f.doc.querySelector=()=>({content:'not-allowed'});assert.equal(child.start(f.win),null);});
  test('child-missing-metadata-rejected',s=>{const f=childFixture(s);f.doc.querySelector=()=>null;assert.equal(child.start(f.win),null);});
  test('child-controls-must-exist',s=>{const f=childFixture(s);f.win.__mapShow=null;f.win.switchTab=null;child.start(f.win);f.domListeners.DOMContentLoaded();assert.equal(f.sent[0].data.state,'error');});
  test('child-content-must-render',s=>{const f=childFixture(s);const q=f.doc.querySelector;f.doc.querySelector=x=>x==='meta[name="dlp-reference-embed"]'?q(x):null;f.doc.getElementById=x=>x==='matrix'?{children:[]}:null;child.start(f.win);f.domListeners.DOMContentLoaded();assert.equal(f.sent[0].data.state,'error');});
  test('child-ready-deduplicated',s=>{const f=childFixture(s);const bridge=child.start(f.win);bridge.ready();bridge.ready();assert.equal(f.sent.length,1);});
  test('child-unknown-content-never-ready',s=>assert.equal(child.contentReady(childFixture(s).win,'nope'),false));
}
if (process.argv[2] === '--list') { console.log(JSON.stringify(cases.map(c=>({id:c.name})))); process.exit(0); }
const selected=process.argv[2];
const results=cases.filter(c=>!selected||c.name===selected).map(c=>{try{c.run();return {id:c.name,pass:true};}catch(e){return {id:c.name,pass:false,error:e.stack};}});
console.log(JSON.stringify(results));
process.exitCode=results.some(r=>!r.pass)?1:0;
