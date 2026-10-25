/* Additive real-browser DLP scope regression. No DOM, fetch, or API mocks. */
import assert from 'node:assert/strict';

export const REQUIRED_DLP_CASE_IDS = [
  'BROWSER-DLP-REQUIRED-01-inline-scope-preserves-explicit-declaration',
  'BROWSER-DLP-REQUIRED-02-inline-assessment-keeps-all-five-controls',
  'BROWSER-DLP-REQUIRED-03-alternative-dependencies-visible-without-reads',
  'BROWSER-DLP-REQUIRED-04-unified-animation-keeps-required-dependencies',
  'BROWSER-DLP-REQUIRED-05-endpoint-shows-inline-controls-not-applicable',
  'BROWSER-DLP-REQUIRED-06-local-tests-never-create-observed-incidents',
];
const required = ['url', 'ssl', 'ftc', 'cac', 'workflow'];
const labels = [/URL filtering/i, /SSL(?:\/TLS)? inspection/i, /File Type Control/i, /Cloud App Control/i, /Workflow Automation/i];
const row = id => `.db-ch-row[data-id="${id}"]`;
const choice = (id, value) => row(id) + ` .db-pill:has(input[value="${value}"])`;

export async function runRequiredDlpControlsAcceptance({test,navigate,click,fill,evaluate,waitFor,state,screenshot}) {
  let beforeLocal, declaration;
  const stageRows = () => evaluate(`Array.from(document.querySelectorAll('#scenarioDetails details > ol > li'),e=>e.textContent)`);
  const readReport = () => evaluate('reportData');
  const indexed = report => {
    assert(Array.isArray(report.required_controls),'Required-control evidence must be in the production report');
    const out = new Map(report.required_controls.map(x=>[x.key,x]));
    for(const key of required)assert(out.has(key),'Missing required dependency '+key);
    return out;
  };
  await test(REQUIRED_DLP_CASE_IDS[0],async()=>{
    await navigate('/');await waitFor(`typeof window.__dbChannelScope === 'function'`);
    // A saved profile applied late would replace the choices made below.
    await waitFor(`window.GD?.profilesReady === true`,15000,'saved profile applied');
    await click('.db-item[data-db="scope"]');
    // Use the real controls to clear previous declarations, then select Web.
    await click('#dbChSelectAll');await click('#dbChSelectAll');
    await click(choice('web_dlp','zscaler'));
    for(const value of await evaluate(`Array.from(document.querySelectorAll('.scope-cb:checked'),e=>e.value)`))if(value!=='dlp')await click(`.scope-cb[value="${value}"]`);
    if(!await evaluate(`document.querySelector('.scope-cb[value=dlp]').checked`))await click('.scope-cb[value="dlp"]');
    declaration=await evaluate('window.__dbChannelScope()');
    assert.equal(declaration.web_dlp.choice,'zscaler');
    for(const id of ['ssl_inspection','cloud_app_control','workflow_automation'])assert.equal(declaration[id].choice,'gap');
    assert(!Object.values(declaration).some(value=>'required_by' in value),'Derived requirements must not overwrite saved choices');
  });
  await test(REQUIRED_DLP_CASE_IDS[1],async()=>{
    await click('.db-item[data-db="configure"]');
    if(await evaluate(`!!document.querySelector('#gdTenantDetails:not([open])')`))await click('#gdTenantDetails > summary');
    await fill('csec','synthetic-browser-fixture-secret');await click('#authBtn');
    await waitFor(`GD.conn?.ok === true && !GD.testing`);
    await click('.db-item[data-db="scope"]');
    const before=(await state()).reads.length;
    await click('#dbScopeRun');
    await waitFor(`!!reportData?.required_controls?.length && !document.getElementById('runBtn').disabled`,20000);
    const report=await readReport(), controls=indexed(report), ids=report.checks.map(x=>x.id);
    for(const key of required){assert(ids.includes('DLP.CTRL.'+key.toUpperCase()));assert.notEqual(controls.get(key).status,'out_of_scope');}
    assert(ids.includes('4.1'));assert(ids.includes('12.4'));
    const reads=(await state()).reads.slice(before);
    for(const endpoint of ['/zia/sslInspectionRules','/zia/urlFilteringRules','/zia/fileTypeRules','/zia/cloudApplicationRules'])assert(reads.includes(endpoint),endpoint);
    assert.deepEqual(await evaluate('window.__dbChannelScope()'),declaration);
    await screenshot('required-dlp-inline-assessment');
  });
  await test(REQUIRED_DLP_CASE_IDS[2],async()=>{
    await click('.db-item[data-db="scope"]');
    for(const id of ['ssl_inspection','cloud_app_control','workflow_automation'])await click(choice(id,'alternative'));
    const before=(await state()).reads.length;
    await click('#dbScopeRun');
    await waitFor(`!document.getElementById('runBtn').disabled && reportData?.required_controls?.find(x=>x.key==='ssl')?.read_permitted === false`,20000);
    const report=await readReport(), controls=indexed(report);
    for(const key of ['ssl','cac','workflow'])assert(['unknown','unverified','unmet'].includes(controls.get(key).status));
    assert(report.checks.some(x=>x.id==='4.1'&&!x.out_of_scope),'Alternative SSL must remain a visible unmet dependency');
    const reads=(await state()).reads.slice(before);
    assert(!reads.includes('/zia/sslInspectionRules'));assert(!reads.includes('/zia/cloudApplicationRules'));
    await screenshot('required-dlp-alternative-evidence');
  });
  await test(REQUIRED_DLP_CASE_IDS[3],async()=>{
    beforeLocal=await state();
    await navigate('/report/motion#live');await waitFor(`!!window.FlowScenario`);
    await fill('scenarioDestination','https://example.test/upload');await fill('scenarioFileType','txt');await fill('scenarioCorpus','SYNTHETIC-FLOW-MARKER only synthetic content');
    await click('#scenarioRun');
    await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('SIMULATED') && !document.getElementById('scenarioRun').disabled`,15000);
    const rows=await stageRows(), svg=await evaluate(`document.querySelector('#scenarioHost svg').textContent`);
    for(const label of labels){assert(rows.some(text=>label.test(text)),String(label));assert(label.test(svg),String(label));}
    for(const label of [/SSL(?:\/TLS)? inspection/i,/Cloud App Control/i,/Workflow Automation incident/i]){
      const stage=rows.find(text=>label.test(text));assert(stage&&!/out_of_scope/i.test(stage));
    }
    assert.equal((await state()).live_polls,beforeLocal.live_polls);
    await screenshot('required-dlp-unified-animation');
  });
  await test(REQUIRED_DLP_CASE_IDS[4],async()=>{
    await fill('scenarioChannel','endpoint');await click('#scenarioRun');
    await waitFor(`document.getElementById('scenarioStatus').textContent.startsWith('SIMULATED · endpoint') && !document.getElementById('scenarioRun').disabled`,15000);
    const rows=await stageRows();
    for(const label of labels.slice(0,4)){const stage=rows.find(text=>label.test(text));assert(stage&&/not_applicable/i.test(stage),label+' must not masquerade as endpoint inline enforcement');}
    assert(rows.some(text=>/Workflow Automation incident/i.test(text)&&!/out_of_scope/i.test(text)));
    await screenshot('required-dlp-endpoint-applicability');
  });
  await test(REQUIRED_DLP_CASE_IDS[5],async()=>{
    const after=await state();
    assert.equal(after.live_polls,beforeLocal.live_polls);
    assert.equal(after.writes,0);assert.deepEqual(after.external_connections,[]);
    assert.equal(await evaluate(`document.querySelectorAll('#liveFeed li').length`),0,'Local test must not populate observed evidence');
    const reads=after.reads.slice(beforeLocal.reads.length);
    assert(!reads.includes('/zia/sslInspectionRules'));assert(!reads.includes('/zia/cloudApplicationRules'));
  });
}
