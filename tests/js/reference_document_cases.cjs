/* Executes the shipped reference scripts with a deliberately small DOM.
 * This covers initialization and navigation logic, not layout/browser CSP. */
const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
const path=require('path');
const root=path.resolve(__dirname,'../..');
const result=[];
function test(id,fn){try{fn();result.push({id,pass:true});}catch(e){result.push({id,pass:false,error:e.stack});}}
function el(tag='div'){
 const classes=new Set(),attrs={},queries=new Map();let content='';
 return {tagName:tag.toUpperCase(),style:{setProperty(){}},dataset:{},children:[],textContent:'',disabled:false,
  classList:{add:x=>classes.add(x),remove:x=>classes.delete(x),toggle:(x,v)=>v===undefined?(classes.has(x)?classes.delete(x):classes.add(x)):(v?classes.add(x):classes.delete(x)),contains:x=>classes.has(x)},
  setAttribute:(k,v)=>attrs[k]=String(v),getAttribute:k=>attrs[k]||null,removeAttribute:k=>delete attrs[k],
  addEventListener(){},removeEventListener(){},focus(){},scrollIntoView(){},
  appendChild(c){this.children.push(c);return c;},
  querySelector(s){if(!queries.has(s))queries.set(s,el());return queries.get(s);},querySelectorAll(){return[];},
  set innerHTML(v){content=v;this.children=[];queries.clear();},get innerHTML(){return content;}
 };
}
function copilot(){
 const html=fs.readFileSync(root+'/static/reference/copilot-readiness.html','utf8');
 const nodes=new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(m=>[m[1],el()]));
 const tabs=['framework','playbook','proposal','pov'];
 const buttons=tabs.map(t=>{const b=el('button');b.setAttribute('onclick',`switchTab('${t}')`);return b});
 const document={body:el('body'),documentElement:el('html'),getElementById:id=>nodes.get(id)||null,
  createElement:tag=>el(tag),addEventListener(){},querySelector:()=>null,
  querySelectorAll:s=>s==='.tab-content'?tabs.map(t=>nodes.get('tab-'+t)):s==='.tab-btn'?buttons:[]};
 const context=vm.createContext({document,console,URL,TextEncoder,TextDecoder,Uint8Array,DataView,Blob,
  atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64'),
  setTimeout:()=>0,clearTimeout(){},alert(){},fetch(){throw Error('Unexpected network request');},
  localStorage:{getItem(){return null},setItem(){}},location:{hash:'',href:'http://localhost:8001/reference/embed/copilot-readiness'},
  window:null});context.window=context;
 context.window.addEventListener=()=>{};context.window.open=()=>null;context.window.scrollTo=()=>{};
 for(const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g))vm.runInContext(m[1],context,{filename:'copilot-readiness.html'});
 return {context,nodes,tabs,buttons,run:code=>vm.runInContext(code,context)};
}
let cp;
test('copilot-readiness/document-initializes-offline',()=>{cp=copilot();assert.equal(cp.nodes.get('matrix').children.length,5);});
if(cp){
 test('copilot-readiness/starts-with-no-selected-channels',()=>assert.equal(cp.run('activeChannels.size'),0));
 test('copilot-readiness/starts-with-rendered-channel-controls',()=>assert.equal(cp.nodes.get('channelToggles').children.length,cp.run('Object.keys(CHANNELS).length')));
 test('copilot-readiness/embedded-catalog-initialized',()=>assert.ok(cp.run('povCatalogRows.length')>0));
 for(const [index,tab] of cp.tabs.entries())test('copilot-readiness/navigate-'+tab,()=>{cp.run(`switchTab('${tab}')`);assert.equal(cp.nodes.get('tab-'+tab).classList.contains('active'),true);assert.equal(cp.buttons[index].classList.contains('active'),true);assert.equal(cp.buttons.filter(b=>b.classList.contains('active')).length,1);});
 test('copilot-readiness/invalid-tab-preserves-selection',()=>{cp.run("switchTab('pov')");assert.equal(cp.run("switchTab('not-a-tab')"),false);assert.equal(cp.nodes.get('tab-pov').classList.contains('active'),true);});
 const channelKeys=Array.from(cp.run('Object.keys(CHANNELS)'));
 for(const key of channelKeys)test('copilot-readiness/filter-'+key,()=>{cp.run(`activeChannels.clear();activeChannels.add(${JSON.stringify(key)});updateAll()`);const n=cp.run(`countTech(${JSON.stringify(key)})`);assert.ok(n>0);assert.ok(cp.nodes.get('efficacyDetail').textContent.includes('1/'+channelKeys.length+' channels'));assert.equal(cp.nodes.get('matrix').children.length,5);});
 test('copilot-readiness/select-visible-queues-mapped-pov',()=>{cp.run("activeChannels.clear();activeChannels.add('saas');updateAll();selectVisibleTechs()");assert.ok(cp.run('selectedTechs.size')>0);assert.ok(cp.run('povSelectedUseCases.size')>0);});
 test('copilot-readiness/clear-capability-selection',()=>{cp.run('clearTechs()');assert.equal(cp.run('selectedTechs.size'),0);assert.equal(cp.nodes.get('framework-export-btn').disabled,true);});
 test('copilot-readiness/select-all-pov',()=>{cp.run('selectAllPov()');assert.equal(cp.run('povSelectedUseCases.size'),cp.run('povCatalogRows.length'));});
 test('copilot-readiness/clear-pov',()=>{cp.run('clearPov()');assert.equal(cp.run('povSelectedUseCases.size'),0);});
 test('copilot-readiness/recommended-pov-restored',()=>{cp.run('selectCorePov()');assert.ok(cp.run('povSelectedUseCases.size')>0);});
 test('copilot-readiness/empty-export-does-not-open-popup',()=>{cp.run('clearTechs();exportWriteupPDF()');assert.equal(cp.run('selectedTechs.size'),0);});
}
function map(){
 const html=fs.readFileSync(root+'/static/reference/portfolio-map.html','utf8');
 const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
 const ids=['chains','channels','dictionary','edmidm','engine','evalall','access','aisec','endpoint','email','saas','sspm','dspm','workflow','setup','troubleshoot','learn','learnsales','learnai'];
 const sections=new Map(ids.map(id=>[id,el('section')])),links=new Map(ids.map(id=>{const a=el('a');a.setAttribute('href','#'+id);return[id,a]})),listeners={},saved=new Map();
 const doc={querySelectorAll:selector=>selector==='nav.sections a'?[...links.values()]:[],getElementById:id=>sections.get(id),addEventListener:(n,fn)=>listeners[n]=fn};
 const context=vm.createContext({document:doc,localStorage:{getItem:k=>saved.get(k),setItem:(k,v)=>saved.set(k,v)},location:{hash:''},history:{replaceState(a,b,url){context.location.hash=url}},window:null});context.window=context;context.scrollTo=()=>{};context.addEventListener=(n,fn)=>listeners[n]=fn;
 vm.runInContext(scripts[0],context);vm.runInContext(scripts[2],context);
 return {context,sections,links,listeners,saved,ids};
}
let mp;
test('portfolio-map/document-navigation-initializes',()=>{mp=map();assert.equal(mp.sections.get('chains').classList.contains('visible'),true);});
if(mp){
 for(const id of mp.ids)test('portfolio-map/navigate-'+id,()=>{let prevented=false;mp.listeners.click({target:{closest:()=>mp.links.get(id)},preventDefault(){prevented=true}});assert.ok(prevented);assert.equal(mp.context.location.hash,'#'+id);assert.equal(mp.sections.get(id).classList.contains('visible'),true);assert.equal([...mp.sections.values()].filter(e=>e.classList.contains('visible')).length,1);assert.equal(mp.links.get(id).classList.contains('active'),true);assert.equal(mp.saved.get('zds-page'),id);});
 test('portfolio-map/invalid-navigation-falls-back',()=>{mp.context.__mapShow('nonexistent');assert.equal(mp.sections.get('chains').classList.contains('visible'),true);});
 test('portfolio-map/browser-hash-navigation',()=>{mp.context.location.hash='#workflow';mp.listeners.hashchange();assert.equal(mp.sections.get('workflow').classList.contains('visible'),true);});
 test('portfolio-map/non-anchor-click-ignored',()=>{mp.listeners.click({target:{closest:()=>null},preventDefault(){throw Error('not an anchor')}});assert.equal(mp.sections.get('workflow').classList.contains('visible'),true);});
}
console.log(JSON.stringify(result));process.exitCode=result.some(r=>!r.pass)?1:0;
