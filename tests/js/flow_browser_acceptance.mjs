/* Real Chrome/CDP acceptance. Production pages and server, no mocked DOM/fetch. */
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import {waitForDebugger, waitForStablePoint, installNativeClickProbe, dispatchNativeClick} from './flow_browser_harness_helpers.mjs';
import {runRequiredDlpControlsAcceptance} from './required_dlp_controls_acceptance.mjs';

const [chrome, base, profile, artifactDir] = process.argv.slice(2);
assert(chrome && base && profile && artifactDir, 'Expected chrome, base URL, profile and artifact directory');
const origin = new URL(base).origin;
await fs.mkdir(profile, {recursive:true});
await fs.mkdir(artifactDir, {recursive:true});
const cases = [], runtimeErrors = [], consoleErrors = [], responses = [], blockedExternal = [];
let browser, ws, sequence = 0, clickSequence = 0, failMapOnce = false, failure, spawnError = null;
const harnessEvents = [];
const pending = new Map();
const dialogAnswers = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const started = Date.now();
let stderr = '';
const watchdog = setTimeout(() => { browser?.kill('SIGKILL'); process.stderr.write('Browser acceptance exceeded 300 seconds\n'); process.exit(2); },300000);

function send(method, params = {}) {
  return new Promise((resolve,reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('CDP timed out: '+method)); }, 10000);
    pending.set(id,{resolve,reject,timer});
    ws.send(JSON.stringify({id,method,params}));
  });
}
async function event(message) {
  if (message.method === 'Page.javascriptDialogOpening') {
    const answer=dialogAnswers.shift();
    if(!answer || answer.type!==message.params.type){
      await send('Page.handleJavaScriptDialog',{accept:false});
      throw Error('Unexpected production dialog: '+message.params.type+' '+message.params.message);
    }
    await send('Page.handleJavaScriptDialog',{accept:true,promptText:answer.text});
  }
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
  await send('Page.bringToFront');
  const token=String(++clickSequence);
  await evaluate(`(()=>{const frame=${frameId?`document.getElementById(${JSON.stringify(frameId)})`:'null'};const doc=frame?frame.contentDocument:document;const el=doc.querySelector(${JSON.stringify(selector)});if(!el)throw Error('Missing click target');if(frame)frame.scrollIntoView({block:'center',behavior:'instant'});el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});window.__acceptanceClickReceipts=window.__acceptanceClickReceipts||{};window.__acceptanceInputProbe=window.__acceptanceInputProbe||{receipts:window.__acceptanceClickReceipts};window.__acceptanceProbeCleanup=window.__acceptanceProbeCleanup||{};window.__acceptanceProbeCleanup[${JSON.stringify(token)}]=(${installNativeClickProbe.toString()})(doc,window.__acceptanceInputProbe,${JSON.stringify(selector)},${JSON.stringify(token)});return true})()`);
  const reveal=()=>evaluate(`(()=>{const frame=${frameId?`document.getElementById(${JSON.stringify(frameId)})`:'null'};const doc=frame?frame.contentDocument:document;const el=doc.querySelector(${JSON.stringify(selector)});if(!el)return false;if(frame)frame.scrollIntoView({block:'center',behavior:'instant'});el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});return true})()`);
  const measure=()=>evaluate(`(()=>{
    const frame=${frameId?`document.getElementById(${JSON.stringify(frameId)})`:'null'};
    const doc=frame?frame.contentDocument:document,el=doc.querySelector(${JSON.stringify(selector)});
    if(!el)return {ready:false,reason:'missing',selector:${JSON.stringify(selector)}};
    const r=el.getBoundingClientRect(),f=frame?frame.getBoundingClientRect():{left:0,top:0};
    const x=r.left+r.width/2,y=r.top+r.height/2,outerX=f.left+x,outerY=f.top+y;
    const sized=r.width>0&&r.height>0,hidden=document.hidden||doc.hidden;
    const inViewport=x>=0&&x<doc.defaultView.innerWidth&&y>=0&&y<doc.defaultView.innerHeight&&outerX>=0&&outerX<innerWidth&&outerY>=0&&outerY<innerHeight;
    const hit=doc.elementFromPoint(x,y),outer=frame?document.elementFromPoint(outerX,outerY):hit;
    const point={ready:!hidden&&!el.disabled&&sized&&inViewport&&(hit===el||el.contains(hit))&&(!frame||outer===frame),
      x:outerX,y:outerY,targetId:window.__acceptanceInputProbe.identify(el),offscreen:sized&&!inViewport,hidden,disabled:!!el.disabled,hit:hit?.tagName,outer:outer?.tagName,selector:${JSON.stringify(selector)}};
    window.__acceptanceInputProbe.actions[${JSON.stringify(token)}].prepared={...point,connected:el.isConnected,activeTargetId:window.__acceptanceInputProbe.identify(doc.activeElement),activeId:doc.activeElement?.id||null,at:performance.now()};
    return point;
  })()`);
  try {
    let point=await waitForStablePoint(measure,{sleep,reveal});
    await send('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x,y:point.y});
    // Recheck both node identity and geometry after hover. Controls can be
    // replaced without changing their position during a profile refresh.
    point=await waitForStablePoint(measure,{sleep,reveal});
    harnessEvents.push({type:'click-dispatched',selector,frameId:frameId||null,...point,at_ms:Date.now()-started});
    await dispatchNativeClick(send,point);
    await waitFor(`window.__acceptanceClickReceipts?.[${JSON.stringify(token)}]?.trusted === true`,1500,'trusted native click on '+selector);
    harnessEvents.push({type:'click',selector,frameId:frameId||null,x:point.x,y:point.y,at_ms:Date.now()-started});
  } finally {
    // Remove only this action's observers; retain its evidence on failure.
    await evaluate(`(()=>{window.__acceptanceProbeCleanup?.[${JSON.stringify(token)}]?.();if(window.__acceptanceProbeCleanup)delete window.__acceptanceProbeCleanup[${JSON.stringify(token)}];return true})()`).catch(()=>{});
  }

}
async function diagnosticState() {
  return evaluate(`({url:location.href,hidden:document.hidden,focused:document.hasFocus(),viewport:{width:innerWidth,height:innerHeight,scale:visualViewport?.scale},scenario:document.getElementById('scenarioStatus')?.textContent,runDisabled:document.getElementById('scenarioRun')?.disabled,lifecycle:window.__acceptanceLifecycle||[],clicks:window.__acceptanceNativeClicks||[],inputActions:Object.values(window.__acceptanceInputProbe?.actions||{}).slice(-10),players:Array.from(document.querySelectorAll('.dsa-player')).filter(p=>p.dataset.status!=='idle').map(p=>({id:p.dataset.flowId,status:p.dataset.status,text:p.querySelector('.dsa-status')?.textContent}))})`);
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
  browser.on('error',error=>{spawnError=error;stderr+=error.stack;});
  const ready = await waitForDebugger({
    readActivePort:()=>fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8'),
    readTargets:async port=>{const response=await fetch(`http://127.0.0.1:${port}/json`,{signal:AbortSignal.timeout(1000)});if(!response.ok)throw Error('CDP HTTP '+response.status);return response.json();},
    hasExited:()=>!!spawnError||browser.exitCode!==null||browser.signalCode!==null,
    diagnostic:()=>`pid=${browser.pid}; exit=${browser.exitCode}; signal=${browser.signalCode}; ${stderr}`,
    sleep, timeoutMs:30000,
  });
  const target=ready.target;
  harnessEvents.push({type:'cdp-ready',port:ready.port,at_ms:Date.now()-started});
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
  await send('Emulation.setFocusEmulationEnabled',{enabled:true});
  await send('Page.bringToFront');
  await send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]});
  await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  await send('Page.addScriptToEvaluateOnNewDocument',{source:`window.__acceptanceLifecycle=[];window.__acceptanceNativeClicks=[];const recordLifecycle=type=>{__acceptanceLifecycle.push({type,hidden:document.hidden,focused:document.hasFocus(),at:performance.now()});if(__acceptanceLifecycle.length>50)__acceptanceLifecycle.shift();};document.addEventListener('visibilitychange',()=>recordLifecycle('visibility'));window.addEventListener('focus',()=>recordLifecycle('focus'));window.addEventListener('blur',()=>recordLifecycle('blur'));window.addEventListener('pagehide',()=>recordLifecycle('pagehide'));matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change',e=>recordLifecycle('motion:'+e.matches));document.addEventListener('click',e=>{const t=e.target.closest('button,a');if(t){__acceptanceNativeClicks.push({id:t.id,action:t.dataset.action,text:t.textContent.slice(0,80),trusted:e.isTrusted,at:performance.now()});if(__acceptanceNativeClicks.length>50)__acceptanceNativeClicks.shift();}},true);window.__acceptanceCsp=[];window.addEventListener('securitypolicyviolation',e=>__acceptanceCsp.push({directive:e.violatedDirective,blocked:e.blockedURI}));try{if(!sessionStorage.getItem('__acceptanceScopeStarted')){localStorage.setItem('zassess_scopes_live_v1',JSON.stringify({scopes:['dlp']}));localStorage.setItem('zassess_channels_v1',JSON.stringify({web_dlp:{choice:'zscaler'},endpoint_dlp:{choice:'zscaler'},email_dlp:{choice:'zscaler'},saas_casb:{choice:'zscaler'},ssl_inspection:{choice:'zscaler'},workflow_automation:{choice:'zscaler'}}));}}catch(e){}`});

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
  // Scope acceptance uses the same trusted native click helper as the existing
  // 19 cases. Tenant responses alone are synthetic; the page, form, profile
  // routes, registry, SSE stream, report renderer and download are production.
  const channelRow=id=>`.db-ch-row[data-id="${id}"]`;
  const channelChoice=(id,choice)=>channelRow(id)+` .db-pill:has(input[value="${choice}"])`;
  const channelState=()=>evaluate(`window.__dbChannelScope()`);
  const prerequisiteText=()=>evaluate(`document.getElementById('dbChPrereqs').textContent`);
  let scopeReadStart, savedProfileId, visibleReport;
  await test('BROWSER-SCOPE-01-production-scope-navigation-is-read-free',async()=>{
    scopeReadStart=(await state()).reads.length;
    await evaluate(`sessionStorage.setItem('__acceptanceScopeStarted','1')`);
    await navigate('/');
    await waitFor(`window.__dbReady && !!document.querySelector('#dbChList .db-ch-row') && typeof _gdProfileSave === 'function'`);
    await click('.db-item[data-db="scope"]');
    await waitFor(`!document.getElementById('dbScopeView').hidden`);
    assert.equal(await evaluate(`document.querySelectorAll('#dbChList .db-ch-row').length`),11);
    assert.equal(await evaluate(`document.getElementById('dbScopeView').contains(document.getElementById('scopeField'))`),true);
    assert.equal((await state()).reads.length,scopeReadStart,'Opening Scope must not read tenant configuration');
    const prerequisiteResponse=await evaluate(`fetch('/api/scope/prerequisites').then(r=>r.json())`);
    assert(prerequisiteResponse.prerequisites.web_dlp.some(p=>p.id==='ssl_inspection'));
  });
  await test('BROWSER-SCOPE-02-gap-prerequisite-is-explained-not-selected',async()=>{
    // Start from the legacy browser fixture declaration; Select all then clear
    // it using the real controls rather than changing page globals or storage.
    await click('#dbChSelectAll');await click('#dbChSelectAll');
    await click(channelChoice('web_dlp','zscaler'));
    await waitFor(`document.getElementById('dbChPrereqs').textContent.includes('included because Inline Web DLP')`);
    const declaration=await channelState();
    assert.equal(declaration.web_dlp.choice,'zscaler');assert.equal(declaration.ssl_inspection.choice,'gap');
    assert.equal(await evaluate(`document.querySelector('${channelRow('ssl_inspection')} input[type=checkbox]').checked`),false);
    assert.equal(await evaluate(`document.querySelector('${channelRow('ssl_inspection')} input[value=zscaler]').checked`),false);
    assert((await evaluate(`document.querySelector('${channelRow('ssl_inspection')} .db-ch-prereq').textContent`)).startsWith('Assessed as a prerequisite:'));
    assert.equal(await evaluate(`JSON.parse(localStorage.getItem('zassess_channels_v1')).ssl_inspection || null`),null);
    assert.equal((await state()).reads.length,scopeReadStart);
    await screenshot('scope-auto-prerequisite');
  });
  await test('BROWSER-SCOPE-03-alternative-prerequisite-stays-excluded',async()=>{
    await click(channelChoice('ssl_inspection','alternative'));
    dialogAnswers.push({type:'prompt',text:'Synthetic alternative vendor'});
    await click(channelRow('ssl_inspection')+' .db-ch-edit');
    await waitFor(`document.querySelector('${channelRow('ssl_inspection')}').textContent.includes('Synthetic alternative vendor')`);
    const declaration=await channelState();
    assert.equal(declaration.ssl_inspection.choice,'alternative');assert.equal(declaration.ssl_inspection.note,'Synthetic alternative vendor');
    const text=await prerequisiteText();assert(text.includes('unmet prerequisite for Inline Web DLP'));assert(text.includes('configuration is not read'));
    const rowNote=await evaluate(`document.querySelector('${channelRow('ssl_inspection')} .db-ch-prereq').textContent`);
    assert(rowNote.startsWith('Unmet prerequisite:'));assert(!rowNote.includes('Assessed as a prerequisite:'));
    assert.equal(await evaluate(`document.querySelector('${channelRow('ssl_inspection')} input[value=alternative]').checked`),true);
    assert.equal((await state()).reads.length,scopeReadStart);
    await screenshot('scope-explicit-alternative-blocked');
  });
  await test('BROWSER-SCOPE-04-dependent-toggle-clears-and-restores-notes',async()=>{
    await click(channelRow('web_dlp')+' .db-ch-check input');
    assert.equal(await evaluate(`document.querySelector('${channelRow('ssl_inspection')} .db-ch-prereq') === null`),true);
    assert((await prerequisiteText()).includes('DLP analysis always includes'));
    assert.equal((await channelState()).ssl_inspection.choice,'alternative');
    await click(channelChoice('web_dlp','zscaler'));
    assert((await prerequisiteText()).includes('unmet prerequisite'));
    await click(channelChoice('ssl_inspection','zscaler'));
    assert.equal(await evaluate(`document.querySelector('${channelRow('ssl_inspection')} .db-ch-prereq') === null`),true);
    assert((await prerequisiteText()).includes('DLP analysis always includes'));
    await click(channelRow('ssl_inspection')+' .db-ch-check input');
    assert.equal((await channelState()).ssl_inspection.choice,'gap');
    assert((await prerequisiteText()).includes('included because Inline Web DLP'));
  });
  await test('BROWSER-SCOPE-05-profile-save-keeps-explicit-gap-declaration',async()=>{
    await click('.db-item[data-db="configure"]');
    await waitFor(`!document.getElementById('dbScopeView') || document.getElementById('dbScopeView').hidden`);
    if(await evaluate(`!!document.querySelector('#gdTenantDetails:not([open])')`))await click('#gdTenantDetails > summary');
    await fill('org','Synthetic Scope Browser');await fill('assessor','Synthetic Assessor');
    await fill('vd','browser-fixture');await fill('cid','synthetic-client');await fill('csec','synthetic-browser-fixture-secret');
    assert.equal(await evaluate(`document.getElementById('gdProfRemember').checked`),false);
    dialogAnswers.push({type:'prompt',text:'Synthetic Scope Browser'});
    await click('button[onclick="_gdProfileSave(true)"]');
    await waitFor(`!!GD.profile && !GD.profileBusy && GD.profileDetail?.channels?.ssl_inspection?.choice === 'gap'`);
    savedProfileId=await evaluate(`GD.profile`);
    const saved=await evaluate(`fetch('/api/tenant-profiles/'+encodeURIComponent(${JSON.stringify(savedProfileId)})).then(r=>r.json())`);
    assert.equal(saved.channels.web_dlp.choice,'zscaler');assert.equal(saved.channels.ssl_inspection.choice,'gap');
    assert.equal(saved.has_secret,false);assert(!('required_by' in saved.channels.ssl_inspection));
    assert.equal((await state()).reads.length,scopeReadStart,'Saving a declaration must not assess the tenant');
    await click('#authBtn');await waitFor(`GD.conn?.ok === true && !GD.testing`);
    assert.equal((await state()).reads.length,scopeReadStart,'Authenticate must not assess the tenant');
  });
  await test('BROWSER-SCOPE-06-assessment-hides-rows-and-keeps-prerequisite',async()=>{
    await click('.db-item[data-db="scope"]');
    // Pick the real DLP registry only. Other product scopes are separate.
    for(const value of await evaluate(`Array.from(document.querySelectorAll('.scope-cb:checked'),e=>e.value)`))if(value!=='dlp')await click(`.scope-cb[value="${value}"]`);
    if(!await evaluate(`document.querySelector('.scope-cb[value=dlp]').checked`))await click('.scope-cb[value="dlp"]');
    const before=(await state()).reads.length;
    await click('#dbScopeRun');
    await waitFor(`!!reportData?.checks?.length && !document.getElementById('runBtn').disabled`,20000,'production scoped SSE assessment');
    visibleReport=await evaluate(`reportData`);
    const ids=visibleReport.checks.map(c=>c.id), fixture=await state();
    assert(ids.includes('4.1'),'Auto-included SSL prerequisite must be assessed');
    assert(!ids.includes('B.1')&&!ids.includes('C.1')&&!ids.includes('D.2'),'Excluded channel checks must not be result rows');
    assert(visibleReport.hidden_checks>0);assert.equal(visibleReport.summary.total,ids.length);
    assert.equal(visibleReport.metadata.total_checks,ids.length);
    assert.equal(ids.length+visibleReport.hidden_checks,fixture.assessment_registry_count);
    assert.equal(await evaluate(`document.querySelectorAll('#checksList .check-item').length`),ids.length);
    assert.equal(await evaluate(`document.querySelectorAll('#scopeNote .scope-hidden').length`),1);
    assert((await evaluate(`document.getElementById('scopeNote').textContent`)).includes(`${visibleReport.hidden_checks} checks are outside the selected scope`));
    assert((await evaluate(`document.getElementById('scopeNote').textContent`)).includes('included because Inline Web DLP'));
    const reads=fixture.reads.slice(before);
    assert(reads.includes('/zia/sslInspectionRules'));assert(reads.includes('/zia/webDlpRules'));
    assert(!reads.some(ep=>/^\/zia\/(endPointDlpRules|emailDlpRules|casbDlpRules)(\/|$)/.test(ep)),'Excluded channels must not be read');
    assert.equal((await channelState()).ssl_inspection.choice,'gap');
    await screenshot('scope-visible-assessment');
  });
  await test('BROWSER-SCOPE-07-json-download-matches-visible-totals',async()=>{
    const downloads=path.join(artifactDir,'scope-downloads');await fs.mkdir(downloads,{recursive:true});
    await send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloads});
    await click('button[onclick="downloadJSON()"]');
    let files=[];const until=Date.now()+30000;   // a busy macOS runner can take longer than 10 s to finish a download
    while(Date.now()<until){files=(await fs.readdir(downloads)).filter(n=>n.endsWith('.json'));if(files.length)break;await sleep(75);}
    assert.equal(files.length,1,'The production Download JSON control must produce a real file');
    const downloaded=JSON.parse(await fs.readFile(path.join(downloads,files[0]),'utf8'));
    assert.deepEqual(downloaded.checks,visibleReport.checks);
    assert.equal(downloaded.summary.total,visibleReport.checks.length);
    assert.equal(downloaded.hidden_checks,visibleReport.hidden_checks);
    assert(!downloaded.checks.some(c=>c.out_of_scope));
    assert.equal(downloaded.channel_coverage.prerequisites.find(p=>p.id==='ssl_inspection').declared,'gap');
  });
  await test('BROWSER-SCOPE-08-profile-update-and-reload-preserve-alternative',async()=>{
    await click('.db-item[data-db="scope"]');await click(channelChoice('ssl_inspection','alternative'));
    dialogAnswers.push({type:'prompt',text:'Synthetic alternative vendor'});await click(channelRow('ssl_inspection')+' .db-ch-edit');
    await click('.db-item[data-db="configure"]');
    if(await evaluate(`!!document.querySelector('#gdTenantDetails:not([open])')`))await click('#gdTenantDetails > summary');
    const updatesBefore=responses.filter(r=>new URL(r.url).pathname==='/api/tenant-profiles').length;
    await click('button[onclick="_gdProfileSave(false)"]');
    await waitFor(`!GD.profileBusy && GD.profileDetail?.channels?.ssl_inspection?.choice === 'alternative'`);
    assert(responses.filter(r=>new URL(r.url).pathname==='/api/tenant-profiles').length>updatesBefore);
    const saved=await evaluate(`fetch('/api/tenant-profiles/'+encodeURIComponent(${JSON.stringify(savedProfileId)})).then(r=>r.json())`);
    assert.equal(saved.channels.ssl_inspection.choice,'alternative');assert.equal(saved.channels.ssl_inspection.note,'Synthetic alternative vendor');
    assert(!('required_by' in saved.channels.ssl_inspection));assert.equal(saved.has_secret,false);
    await navigate('/');
    await waitFor(`GD.profileDetail?.channels?.ssl_inspection?.choice === 'alternative' && window.__dbChannelScope?.().ssl_inspection.choice === 'alternative'`);
    await click('.db-item[data-db="scope"]');
    await waitFor(`document.getElementById('dbChPrereqs').textContent.includes('unmet prerequisite for Inline Web DLP')`);
    assert.equal((await channelState()).ssl_inspection.note,'Synthetic alternative vendor');
  });
  await test('BROWSER-SCOPE-09-blocked-assessment-never-reads-excluded-ssl',async()=>{
    await click('.db-item[data-db="configure"]');
    if(await evaluate(`!!document.querySelector('#gdTenantDetails:not([open])')`))await click('#gdTenantDetails > summary');
    await fill('csec','synthetic-browser-fixture-secret');
    await click('#authBtn');await waitFor(`GD.conn?.ok === true && !GD.testing`);
    await click('.db-item[data-db="scope"]');
    const before=(await state()).reads.length;
    await click('#dbScopeRun');
    await waitFor(`!!reportData?.checks?.length && !document.getElementById('runBtn').disabled && reportData.channel_coverage?.alternative?.some(c=>c.id==='ssl_inspection')`,20000,'blocked-prerequisite scoped assessment');
    const report=await evaluate(`reportData`),ids=report.checks.map(c=>c.id);
    assert(ids.includes('4.1')&&ids.includes('A.2'),'Alternative SSL must remain a visible unmet dependency');
    const required=new Map(report.required_controls.map(x=>[x.key,x]));
    for(const key of ['ssl','cac','workflow'])assert(required.has(key));
    assert.equal(required.get('ssl').status,'unverified');
    assert.equal(required.get('ssl').read_permitted,false);
    assert(report.checks.filter(x=>x.id==='4.1'||x.id==='A.2').every(x=>x.status==='INFO'&&!x.out_of_scope));
    const blocked=report.channel_coverage.prerequisites.find(p=>p.id==='ssl_inspection');
    assert(blocked && blocked.blocked && blocked.declared==='alternative');
    assert((await evaluate(`document.getElementById('scopeNote').textContent`)).includes('unmet prerequisite'));
    assert(!(await state()).reads.slice(before).some(ep=>ep.startsWith('/zia/sslInspectionRules')));
    assert.equal(await evaluate(`document.querySelectorAll('#checksList .check-item').length`),ids.length);
    assert.equal(report.summary.total,ids.length);assert.equal(dialogAnswers.length,0);
    await screenshot('scope-blocked-assessment');
  });
  await test('BROWSER-SCOPE-10-excluded-ssl-keeps-unified-path-controls',async()=>{
    const before=(await state()).reads.length;
    await navigate('/report/motion#live');
    await waitFor(`!!window.FlowScenario && !!document.querySelector('#liveHost svg')`);
    assert.equal(await evaluate(`JSON.parse(localStorage.getItem('zassess_channels_v1')).ssl_inspection.choice`),'alternative');
    await fill('scenarioDestination','https://example.test/upload');await fill('scenarioFileType','txt');await fill('scenarioCorpus','SYNTHETIC-FLOW-MARKER one synthetic record');
    await click('#scenarioRun');
    await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('SIMULATED') && !document.getElementById('scenarioRun').disabled`,15000);
    const stages=await evaluate(`Array.from(document.querySelectorAll('#scenarioDetails details > ol > li'),e=>e.textContent)`);
    for(const expected of ['URL filtering','SSL inspection','File Type Control','Cloud App Control','Workflow Automation']){
      assert(stages.some(text=>text.toLowerCase().includes(expected.toLowerCase())),expected+' evidence panel disappeared');
      assert((await evaluate(`document.querySelector('#scenarioHost svg').textContent`)).toLowerCase().includes(expected.toLowerCase()),expected+' flow box disappeared');
    }
    const ssl=stages.find(text=>/^SSL inspection/i.test(text));
    assert(ssl && /unverified|unknown|unmet/i.test(ssl) && !/out_of_scope/i.test(ssl),'Alternative SSL must remain an unmet required control');
    assert(!(await state()).reads.slice(before).some(ep=>ep.startsWith('/zia/sslInspectionRules')),'Unified path must not read explicitly excluded SSL');
    await screenshot('scope-excluded-ssl-path-controls');
  });
  await runRequiredDlpControlsAcceptance({test,navigate,click,fill,evaluate,waitFor,state,screenshot});
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
  if(ws?.readyState===WebSocket.OPEN){try{await screenshot('failure');await fs.writeFile(path.join(artifactDir,'failure-state.json'),JSON.stringify(await diagnosticState(),null,2));}catch{}}
} finally {
  let fixtureState=null;
  if(ws?.readyState===WebSocket.OPEN){try{fixtureState=await state();}catch{}}
  await fs.writeFile(path.join(artifactDir,'results.json'),JSON.stringify({elapsed_ms:Date.now()-started,cases,harnessEvents,runtimeErrors,consoleErrors,blockedExternal,fixture_state:fixtureState,failure:failure?.stack||null},null,2));
  await fs.writeFile(path.join(artifactDir,'chrome.stderr'),stderr);
  clearTimeout(watchdog);for(const callback of pending.values())clearTimeout(callback.timer);
  if(ws)ws.close();if(browser)browser.kill('SIGTERM');
}
if(failure)process.exitCode=1;
else process.stdout.write(JSON.stringify({passed:cases.length,elapsed_ms:Date.now()-started,artifacts:artifactDir})+'\n');
