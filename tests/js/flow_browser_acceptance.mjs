/* Real Chrome/CDP acceptance. Production pages and server, no mocked DOM/fetch. */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const [chrome, base, profile, artifactDir] = process.argv.slice(2);
assert(chrome && base && profile && artifactDir, 'Expected chrome, base URL, profile and artifact directory');
const origin = new URL(base).origin;
await fs.mkdir(profile, {recursive:true});
await fs.mkdir(artifactDir, {recursive:true});
const cases = [], runtimeErrors = [], consoleErrors = [], responses = [], blockedExternal = [];
let browser, ws, sequence = 0, failMapOnce = false, failure;
const pending = new Map();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const started = Date.now();
let stderr = '';
const watchdog = setTimeout(() => { browser?.kill('SIGKILL'); process.stderr.write('Browser acceptance exceeded 105 seconds\n'); process.exit(2); },105000);

function send(method, params = {}) {
  return new Promise((resolve,reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('CDP timed out: '+method)); }, 10000);
    pending.set(id,{resolve,reject,timer});
    ws.send(JSON.stringify({id,method,params}));
  });
}
async function event(message) {
  if (message.method === 'Runtime.exceptionThrown') runtimeErrors.push(message.params.exceptionDetails);
  if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') consoleErrors.push(message.params.entry);
  if (message.method === 'Network.responseReceived') {
    const response=message.params.response;
    responses.push({url:response.url,status:response.status,headers:response.headers});
  }
  if (message.method === 'Fetch.requestPaused') {
    const {requestId,request} = message.params;
    const url = new URL(request.url);
    if (url.origin !== origin && !['data:','about:','blob:'].includes(url.protocol)) {
      blockedExternal.push(request.url);
      await send('Fetch.failRequest',{requestId,errorReason:'BlockedByClient'});
    } else if (failMapOnce && url.pathname === '/reference/embed/portfolio-map') {
      failMapOnce=false;
      await send('Fetch.failRequest',{requestId,errorReason:'Failed'});
    } else await send('Fetch.continueRequest',{requestId});
  }
}
async function evaluate(expression) {
  const result = await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
  if (result.exceptionDetails) throw new Error('Page expression failed: '+expression+'\n'+JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function waitFor(expression, timeout=10000, label=expression) {
  const until=Date.now()+timeout;
  let value;
  while(Date.now()<until) {
    try {value=await evaluate(expression);if(value)return value;} catch(error) { if(Date.now()+150>=until)throw error; }
    await sleep(75);
  }
  throw new Error('Timed out waiting for '+label+'; last='+JSON.stringify(value));
}
async function navigate(route) {
  await send('Page.navigate',{url:base+route});
  await waitFor(`document.readyState === 'complete' && location.pathname === ${JSON.stringify(route.split('#')[0])}`,15000,'production navigation '+route);
}
async function click(selector, frameId) {
  const point=await evaluate(`(()=>{const frame=${frameId?`document.getElementById(${JSON.stringify(frameId)})`:'null'};const doc=frame?frame.contentDocument:document;const el=doc.querySelector(${JSON.stringify(selector)});if(!el)throw Error('Missing click target');el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});if(frame)frame.scrollIntoView({block:'center',behavior:'instant'});const r=el.getBoundingClientRect(), f=frame?frame.getBoundingClientRect():{left:0,top:0};if(r.width<1||r.height<1)throw Error('Click target not visible');return{x:f.left+r.left+r.width/2,y:f.top+r.top+r.height/2}})()`);
  await send('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x,y:point.y});
  await send('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',buttons:1,clickCount:1,...point});
  await send('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',buttons:0,clickCount:1,...point});
}
async function fill(id,value) {
  await evaluate(`(()=>{const e=document.getElementById(${JSON.stringify(id)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
}
async function screenshot(name) {
  const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
  await fs.writeFile(path.join(artifactDir,name+'.png'),Buffer.from(shot.data,'base64'));
}
async function test(id, run) {
  const at=Date.now();
  try {await run();cases.push({id,passed:true,elapsed_ms:Date.now()-at});}
  catch(error){cases.push({id,passed:false,elapsed_ms:Date.now()-at,error:error.stack});throw error;}
}
async function state(){return evaluate(`fetch('/__browser_test__/state').then(r=>r.json())`);}

try {
  browser=spawn(chrome,['--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',`--user-data-dir=${profile}`,
    '--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-dev-shm-usage',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost','--window-size=1440,1100','about:blank'],{stdio:['ignore','ignore','pipe']});
  browser.stderr.on('data',chunk=>{stderr+=chunk.toString();});
  browser.on('error',error=>{stderr+=error.stack;});
  let debuggingPort;
  for(let attempt=0;attempt<100;attempt++) {
    try {debuggingPort=(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];if(debuggingPort)break;}catch{}
    if(browser.exitCode!==null)throw new Error('Chrome exited before CDP: '+stderr);
    await sleep(100);
  }
  assert(debuggingPort,'Chrome did not expose CDP; '+stderr);
  const targets=await (await fetch(`http://127.0.0.1:${debuggingPort}/json`)).json();
  const target=targets.find(item=>item.type==='page');
  assert(target,'Chrome created no page target');
  ws=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  ws.onmessage=message=>{
    const data=JSON.parse(message.data);
    if(data.id && pending.has(data.id)) {
      const callback=pending.get(data.id);pending.delete(data.id);clearTimeout(callback.timer);
      if(data.error)callback.reject(new Error(JSON.stringify(data.error)));else callback.resolve(data.result || {});
    } else event(data).catch(error=>{runtimeErrors.push({driver_event_error:error.stack});});
  };
  await Promise.all([send('Page.enable'),send('Runtime.enable'),send('Log.enable'),send('Network.enable')]);
  await send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  await send('Page.addScriptToEvaluateOnNewDocument',{source:`window.__acceptanceCsp=[];window.addEventListener('securitypolicyviolation',e=>__acceptanceCsp.push({directive:e.violatedDirective,blocked:e.blockedURI}));try{localStorage.setItem('zassess_scopes_live_v1',JSON.stringify({scopes:['dlp']}));localStorage.setItem('zassess_channels_v1',JSON.stringify({web_dlp:{choice:'zscaler'},endpoint_dlp:{choice:'zscaler'},email_dlp:{choice:'zscaler'},saas_casb:{choice:'zscaler'},ssl_inspection:{choice:'zscaler'},workflow_automation:{choice:'zscaler'}}));}catch(e){}`});

  await test('BROWSER-FLOW-01-production-workspace-is-interactive',async()=>{
    await navigate('/report/motion#live');
    await waitFor(`!!window.FlowScenario && !!document.querySelector('#liveHost svg')`);
    const before=await state();assert.equal(before.live_polls,0);assert.equal(before.reads.length,0);
    assert.equal(await evaluate(`getComputedStyle(document.getElementById('scenarioWorkspace')).display !== 'none'`),true);
  });
  await test('BROWSER-FLOW-02-shared-synthetic-input-runs-real-endpoint',async()=>{
    await fill('scenarioDestination','https://example.test/upload');await fill('scenarioFileType','txt');await fill('scenarioCorpus','SYNTHETIC-FLOW-MARKER one synthetic record');
    await click('#scenarioRun');
    await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('SIMULATED') && !document.getElementById('scenarioRun').disabled`,15000,'synthetic scenario result');
    const text=await evaluate(`document.getElementById('scenarioDetails').textContent`);
    for(const expected of ['Synthetic test marker','101','Synthetic marker engine','201','Synthetic monitor','301','Workflow Automation','URL filtering','SSL inspection','File Type Control'])assert(text.includes(expected),expected);
    assert((await state()).reads.length>0);assert.equal((await state()).live_polls,0);
    await screenshot('flow-simulation-desktop');
  });
  await test('BROWSER-FLOW-03-guided-next-and-play-use-production-svg',async()=>{
    await click('#scenarioNext');await waitFor(`document.querySelectorAll('#scenarioTranscript li').length === 1`);
    await sleep(350);assert.equal(await evaluate(`document.querySelectorAll('#scenarioTranscript li').length`),1);
    await click('#scenarioPlay');await waitFor(`document.getElementById('scenarioStatus').textContent.includes('Animation complete')`);
    assert((await evaluate(`document.querySelectorAll('#scenarioTranscript li').length`))>3);
  });
  await test('BROWSER-FLOW-04-observed-fixture-and-demo-counters-are-isolated',async()=>{
    await click('#liveStart');await waitFor(`document.getElementById('liveVerdict').textContent.includes('1 unique incidents')`);
    const text=await evaluate(`document.getElementById('liveVerdict').textContent`);
    await click('#liveSample');await waitFor(`document.getElementById('liveDemoStatus').textContent.includes('DEMO')`);
    assert.equal(await evaluate(`document.getElementById('liveVerdict').textContent`),text);
    assert.equal(await evaluate(`document.querySelectorAll('#liveFeed li').length`),1);
    await click('#liveStop');assert.equal(await evaluate(`document.querySelectorAll('#liveHost svg').length`),0);
    assert.equal(await evaluate(`document.querySelectorAll('#liveFeed li').length`),1);
    await screenshot('flow-live-demo-separated');
  });
  await test('BROWSER-FLOW-05-configuration-only-is-not-simulated',async()=>{
    await click('#scenarioTrace');await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('CONFIGURATION') && !document.getElementById('scenarioTrace').disabled`,15000);
    await click('#tab-dlp');
    assert((await evaluate(`document.getElementById('dlpSrc').textContent`)).includes('CONFIGURATION'));
    assert.equal(await evaluate(`document.getElementById('dlpReplay').disabled`),true);
  });
  await test('BROWSER-FLOW-06-mobile-inputs-and-no-horizontal-page-overflow',async()=>{
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await click('#tab-live');
    assert.equal(await evaluate(`document.getElementById('scenarioCorpus').getBoundingClientRect().width > 100`),true);
    assert.equal(await evaluate(`document.documentElement.scrollWidth <= innerWidth + 2`),true);
    await screenshot('flow-mobile');
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  });

  await test('BROWSER-FLOW-07-normal-motion-packets-move-and-restart-clears',async()=>{
    await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'no-preference'}]});
    await click('#scenarioRun');
    await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('SIMULATED') && !document.getElementById('scenarioRun').disabled`,15000);
    await click('#scenarioPlay');
    await waitFor(`!!document.querySelector('#scenarioHost .fa-dot')`);
    const first=await evaluate(`(()=>{const p=document.querySelector('#scenarioHost .fa-dot');return [p.getAttribute('cx'),p.getAttribute('cy')]})()`);
    await sleep(120);
    const moved=await evaluate(`(()=>{const p=document.querySelector('#scenarioHost .fa-dot');return p?[p.getAttribute('cx'),p.getAttribute('cy')]:null})()`);
    assert(moved,'Normal-motion packet disappeared before its first hop completed');assert.notDeepEqual(moved,first,'A real animation packet must change position');
    await screenshot('flow-normal-motion-packet');
    await click('#scenarioRestart');
    assert.equal(await evaluate(`document.querySelectorAll('#scenarioHost .fa-dot').length`),0);
    await sleep(200);assert.equal(await evaluate(`document.querySelectorAll('#scenarioHost .fa-dot').length`),0);
    await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  });

  await test('BROWSER-EMBED-01-parent-production-reference-loads',async()=>{
    await navigate('/reference/data-security-portfolio-framework');
    await waitFor(`typeof ReferenceEmbeds === 'object' && !!document.getElementById('mapFrame')`);
    assert.equal(await evaluate(`document.getElementById('mapFrame').getAttribute('src')`),null);
  });
  await test('BROWSER-EMBED-02-failed-frame-shows-real-retry-control',async()=>{
    failMapOnce=true;
    await click(`button[onclick*="switchTab('map')"]`);
    await waitFor(`document.getElementById('mapFrame').dataset.state === 'error'`,19000,'injected network-failure timeout');
    assert.equal(await evaluate(`document.getElementById('mapFrameRetry').hidden`),false);
    await screenshot('portfolio-retry-state');
  });
  await test('BROWSER-EMBED-03-retry-loads-real-child-under-production-csp',async()=>{
    const first=await evaluate(`document.getElementById('mapFrame').src`);
    await click('#mapFrameRetry');await waitFor(`document.getElementById('mapFrame').dataset.state === 'ready'`,15000,'portfolio ready handshake');
    assert.notEqual(await evaluate(`document.getElementById('mapFrame').src`),first);
    assert((await evaluate(`document.getElementById('mapFrame').contentDocument.title`)).includes('Portfolio Map'));
    assert.equal(await evaluate(`document.getElementById('mapFrame').contentWindow.__acceptanceCsp.length`),0);
    const response=responses.findLast(r=>new URL(r.url).pathname==='/reference/embed/portfolio-map' && r.status===200);
    assert(response,'No real HTTP response for embedded portfolio');
    const headers=Object.fromEntries(Object.entries(response.headers).map(([k,v])=>[k.toLowerCase(),v]));
    assert.equal(headers['x-frame-options'],'SAMEORIGIN');assert(headers['content-security-policy'].includes("frame-ancestors 'self'"));
    await screenshot('portfolio-embedded-loaded');
  });
  await test('BROWSER-EMBED-04-nested-portfolio-tab-navigation-works',async()=>{
    await click('nav.sections a[href="#engine"]','mapFrame');
    await waitFor(`document.getElementById('mapFrame').contentDocument.getElementById('engine').classList.contains('visible')`);
    assert.equal(await evaluate(`document.getElementById('mapFrame').contentDocument.getElementById('chains').classList.contains('visible')`),false);
  });
  await test('BROWSER-EMBED-05-copilot-child-loads-and-inner-tabs-work',async()=>{
    await click(`button[onclick*="switchTab('copilot')"]`);
    await waitFor(`document.getElementById('copilotFrame').dataset.state === 'ready'`,15000,'copilot ready handshake');
    assert((await evaluate(`document.getElementById('copilotFrame').contentDocument.title`)).includes('Copilot Readiness'));
    await click(`button[onclick="switchTab('playbook')"]`,'copilotFrame');
    await waitFor(`document.getElementById('copilotFrame').contentDocument.getElementById('tab-playbook').classList.contains('active')`);
    assert.equal(await evaluate(`document.getElementById('copilotFrame').contentWindow.__acceptanceCsp.length`),0);
    await screenshot('copilot-embedded-adoption');
  });
  await test('BROWSER-EMBED-06-switching-parent-tabs-retains-ready-frames',async()=>{
    const before=await evaluate(`document.getElementById('mapFrame').src`);
    await click(`button[onclick*="switchTab('map')"]`);
    assert.equal(await evaluate(`document.getElementById('mapFrame').src`),before);
    assert.equal(await evaluate(`document.getElementById('mapFrame').dataset.state`),'ready');
    assert.equal(await evaluate(`__acceptanceCsp.length`),0);
  });

  const panel='.dsa-player[data-flow-id="chains-1"]';
  const dsaState=()=>evaluate(`(()=>{const p=document.querySelector(${JSON.stringify(panel)});return{status:p.dataset.status,text:p.querySelector('.dsa-status').textContent,active:p.querySelector('[aria-current="step"]')?.dataset.stageId,states:Array.from(p.querySelectorAll('.dsa-timeline li'),x=>x.dataset.state)}})()`);
  await test('BROWSER-DSA-01-all-44-production-players-have-complete-controls',async()=>{
    await navigate('/reference/data-security-architect');
    await waitFor(`document.querySelectorAll('.dsa-player').length === 44`,15000);
    const result=await evaluate(`Array.from(document.querySelectorAll('.dsa-player'),p=>({id:p.dataset.flowId,actions:Array.from(p.querySelectorAll('[data-action]'),b=>b.dataset.action),stages:p.querySelectorAll('.dsa-timeline li').length,label:p.querySelector('.dsa-sample').textContent,gates:p.querySelector('.dsa-gates').textContent}))`);
    assert.equal(new Set(result.map(p=>p.id)).size,44);
    for(const p of result){assert.deepEqual(p.actions,['PLAY','GUIDED','BACK','NEXT','REPLAY','PAUSE','RESUME','RESTART']);assert(p.stages>1);assert(p.label.includes('REFERENCE SAMPLE'));for(const control of ['URL Filtering','SSL/TLS Inspection','File Type Control'])assert(p.gates.includes(control));}
  });
  await test('BROWSER-DSA-02-guided-demo-waits-for-next',async()=>{
    await click(panel+' [data-action="GUIDED"]');const first=await dsaState();
    assert.equal(first.status,'guided');await sleep(2400);assert.equal((await dsaState()).active,first.active);
    await click(panel+' [data-action="NEXT"]');assert.notEqual((await dsaState()).active,first.active);
    await screenshot('dsa-guided-next');
  });
  await test('BROWSER-DSA-03-play-pause-resume-and-restart-are-real',async()=>{
    await fill('dsa-speed-chains-1','2');await click(panel+' [data-action="PLAY"]');
    const first=await dsaState();await waitFor(`document.querySelector(${JSON.stringify(panel)}).querySelector('[aria-current="step"]').dataset.stageId !== ${JSON.stringify(first.active)}`,4000);
    await click(panel+' [data-action="PAUSE"]');const paused=await dsaState();assert.equal(paused.status,'paused');await sleep(1300);assert.equal((await dsaState()).active,paused.active);
    await click(panel+' [data-action="RESUME"]');await waitFor(`document.querySelector(${JSON.stringify(panel)}).querySelector('[aria-current="step"]').dataset.stageId !== ${JSON.stringify(paused.active)}`,4000);
    await click(panel+' [data-action="RESTART"]');const reset=await dsaState();assert.equal(reset.status,'idle');await sleep(1250);assert.equal((await dsaState()).status,'idle');
  });
  await test('BROWSER-DSA-04-play-all-reaches-terminal-state',async()=>{
    await click(panel+' [data-action="PLAY"]');await waitFor(`document.querySelector(${JSON.stringify(panel)}).dataset.status === 'complete'`,18000,'Play All complete');
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(panel)}).querySelector('[data-action="NEXT"]').disabled`),true);
    await screenshot('dsa-play-all-complete');
  });
  await test('BROWSER-DSA-05-only-one-player-runs-and-reduced-motion-is-honored',async()=>{
    await click(panel+' [data-action="PLAY"]');const second='.dsa-player[data-flow-id="chains-2"]';await click(second+' [data-action="PLAY"]');
    assert.equal((await dsaState()).status,'paused');
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(second)}).dataset.reducedMotion`),'true');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector(${JSON.stringify(second)}).querySelector('.dsa-packet')).animationName`),'none');
    await click(second+' [data-action="PAUSE"]');
  });
  await test('BROWSER-SAFETY-01-no-runtime-csp-errors-tenant-writes-or-external-requests',async()=>{
    assert.deepEqual(runtimeErrors,[],'Unexpected runtime errors');
    assert.deepEqual(blockedExternal,[],'Production page attempted external resources');
    const cspErrors=consoleErrors.filter(e=>/content security policy|refused to (frame|execute|load)|x-frame-options/i.test(e.text||''));
    assert.deepEqual(cspErrors,[],'Browser-enforced CSP/frame error');
    assert.equal(await evaluate(`__acceptanceCsp.length`),0);
    const fixture=await state();assert.equal(fixture.writes,0);assert.deepEqual(fixture.external_connections,[]);assert(fixture.live_polls>0);
  });
} catch(error) {
  failure=error;
  process.stderr.write(error.stack+'\n');
  if(ws?.readyState===WebSocket.OPEN){try{await screenshot('failure');}catch{}}
} finally {
  let fixtureState=null;
  if(ws?.readyState===WebSocket.OPEN){try{fixtureState=await state();}catch{}}
  await fs.writeFile(path.join(artifactDir,'results.json'),JSON.stringify({elapsed_ms:Date.now()-started,cases,runtimeErrors,consoleErrors,blockedExternal,fixture_state:fixtureState,failure:failure?.stack||null},null,2));
  await fs.writeFile(path.join(artifactDir,'chrome.stderr'),stderr);
  clearTimeout(watchdog);for(const callback of pending.values())clearTimeout(callback.timer);
  if(ws)ws.close();if(browser)browser.kill('SIGTERM');
}
if(failure)process.exitCode=1;
else process.stdout.write(JSON.stringify({passed:cases.length,elapsed_ms:Date.now()-started,artifacts:artifactDir})+'\n');
