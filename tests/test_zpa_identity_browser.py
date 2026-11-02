"""The ZPA identity in a real browser (headless Chrome over CDP, as
tests/test_findings_reflow.py drives it): the real app serves the real
Path analyzer page; the ZPA identity pickers and the job endpoints answer
with fixtures through the CDP Fetch domain, so no tenant is read.

Checked: with ZPA in scope the IdPs load into the picker and a user's SCIM
groups preview; the start request carries exactly the identity typed and
picked; the result's "ZPA identity" block names the condition that decided,
with tenant strings drawn as text; without ZPA in scope the buttons are
off and the page says why; every new control is labelled and reachable by
keyboard; nothing scrolls sideways at 320px. Optional screenshots go to
$ZID_SHOTS. Skips without node or Chrome.
"""
from __future__ import annotations

import json
import os

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

XSS = '<img src=x onerror="window.__xss=1">'

IDPS = {"idps": [{"id": "216196257331281111", "name": "Okta", "enabled": True, "scim_enabled": True, "scim_policy": True},
                 {"id": "216196257331282222", "name": "Entra " + XSS, "enabled": True, "scim_enabled": False}],
        "saml_attributes": [{"id": "1", "name": "Department_Okta", "saml_name": "department", "idp_id": "216196257331281111"}], "error": None}
USER = {"idp": "216196257331281111", "user": "jane.doe@acme.example", "groups": [{"id": "9", "name": "Finance"}, {"id": "8", "name": XSS}],
        "group_count": 2, "complete": True, "error": None}


def _result():
    """A Path analyzer result for git.corp.example with the ZPA identity block,
    built by the same functions the start endpoint uses."""
    import zpa_identity as zi
    import zpa_path as zp
    from test_zpa_identity import data, IdClient
    from test_zpa_analysis import FakeTenant
    import zpa_reader
    zpa_reader.PACE_SECONDS = 0.0
    sn, prof = zp.read(FakeTenant(data()), pace=0)
    p = zi.parse({"idp": "idp1", "user": "jane.doe@acme.example", "attributes": "department=Finance"})
    ident = zi.resolve(p, sn, zi.Lookups(IdClient()))
    st = zp.stage(sn, zp.destination("git.corp.example", None), profiles=prof, identity=ident)
    pd = {"input": "git.corp.example", "host": "git.corp.example", "kind": "host", "is_ip": False, "private": False, "port": None, "path": ""}
    res = zp.standalone(st["hops"], st["modules"], outcome=st["outcome"], headline=st["headline"], summary=st["summary"], dest=pd, network="off",
                        platform="windows", scope={"summary": "ZPA only.", "read": [], "not_in_scope": {}}, impacts=st["impacts"],
                        assumptions=st["assumptions"], stops_at=None, blocked_by=None, reaches_zscaler=True)
    res["zpa_identity"] = st["identity"]
    res["zpa_identity"]["unknown"] = res["zpa_identity"]["unknown"] + [XSS]
    res["logs"] = []
    return res


DRIVER = CDP_PRELUDE + r"""
const F = JSON.parse(args[0]);
const shots = args[1];
const handlers = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } else if (m.method) handlers.forEach(h => h(m)); };
const seen = { zid: [], start: null, errors: [] };
handlers.push(m => { if (m.method === 'Runtime.exceptionThrown') seen.errors.push(m.params.exceptionDetails.text); });
handlers.push(async m => {
  if (m.method !== 'Fetch.requestPaused') return;
  const u = m.params.request.url, post = m.params.request.postData ? JSON.parse(m.params.request.postData) : {};
  let body = null;
  if (u.includes('/api/path-analyzer/zpa-identity')) { seen.zid.push(post); body = post.action === 'user' ? F.user : F.idps; }
  else if (u.includes('/api/path-analyzer/start')) { seen.start = post; body = { job_id: 'zidjob', status: 'running' }; }
  else if (u.includes('/jobs/zidjob')) body = { status: 'done', result: F.result, logs: [], next: 1, elapsed_seconds: 1 };
  if (!body) { await send('Fetch.continueRequest', { requestId: m.params.requestId }); return; }
  await send('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
});
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/path-analyzer/zpa-identity*' }, { urlPattern: '*/api/path-analyzer/start*' }, { urlPattern: '*/api/dlp-packs/jobs/*' }] });
async function shot(name, sel) {
  if (!shots) return;
  const r = await ev(`(() => { document.querySelectorAll('.rp-bar').forEach(b => { b.style.position = 'static'; }); const e = document.querySelector(${JSON.stringify(sel)}); e.scrollIntoView({block:'start'}); const b = e.getBoundingClientRect(); return {x:b.left, y:b.top + scrollY, w:b.width, h:Math.min(b.height, 1600)}; })()`);
  await sleep(300);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 } });
  fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(s.result.data, 'base64'));
}
async function go(width, scopes) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + '/report/path' });
  await until(() => ev(`document.readyState === 'complete' && !!window.PathWhatIf`), 'load');
  await ev(`(localStorage.setItem('zassess_scopes_live_v1', ${JSON.stringify(JSON.stringify({ scopes }))}), 1)`);
  await send('Page.reload');
  await until(() => ev(`document.readyState === 'complete' && !!document.getElementById('paWiZpa')`), 'reload');
  await ev(`(document.getElementById('paWhatIf').open = true, document.getElementById('paWhatIf').dispatchEvent(new Event('toggle')), 1)`);
}
const out = {};
await send('Runtime.enable');

// 1. ZPA not in scope: the buttons are off and the page says why.
await go(1280, ['dlp']);
out.off = await ev(`({ load: document.getElementById('paWiZ_load').disabled, find: document.getElementById('paWiZ_find').disabled, hint: document.getElementById('paWiZScope').textContent })`);

// 2. In scope: load the IdPs, pick one, preview the user's groups, type attributes, analyze.
await go(1280, ['zpa']);
await ev(`(document.getElementById('paWiZ_load').click(), 1)`);
await until(() => ev(`document.querySelectorAll('#paWiZ_idp option').length === 3`), 'the IdPs');
await ev(`(() => { const s = document.getElementById('paWiZ_idp'); s.value = '216196257331281111'; s.dispatchEvent(new Event('change')); document.getElementById('paWiZ_user').value = 'jane.doe@acme.example'; document.getElementById('paWiZ_find').click(); return 1; })()`);
await until(() => ev(`!document.getElementById('paWiZRes').hidden && /SCIM group/.test(document.getElementById('paWiZRes').textContent)`), 'the groups');
out.picker = await ev(`({ options: [...document.querySelectorAll('#paWiZ_idp option')].map(o => o.textContent), groups: document.getElementById('paWiZRes').textContent,
  attrHint: document.getElementById('paWiZAttrHint').textContent, xss: !!window.__xss, imgs: document.querySelectorAll('#paWiZpa img').length })`);
await shot('zid_whatif', '#paWhatIf');
await ev(`(document.getElementById('paWiZ_attrs').value = 'Department=Finance', document.getElementById('paDest').value = 'git.corp.example', document.getElementById('paRun').click(), 1)`);
await until(() => ev(`!!document.getElementById('paZidOut')`), 'the ZPA identity block', 20000);
out.result = await ev(`(() => { const z = document.getElementById('paZidOut'); return { text: z.textContent.replace(/\\s+/g, ' '), headline: (document.querySelector('.pa-verdict') || {}).textContent || '',
  xss: !!window.__xss, imgs: z.querySelectorAll('img').length, heading: z.querySelector('h2').textContent }; })()`);
out.start = seen.start && seen.start.identity;
out.zid = seen.zid.map(b => ({ action: b.action, idp: b.idp, user: b.user, scopes: b.scopes }));
await shot('zid_result', '#paZidOut');

// 3. Labels and the keyboard: each new control has a name and takes focus.
out.a11y = await ev(`['paWiZ_idp', 'paWiZ_load', 'paWiZ_user', 'paWiZ_find', 'paWiZ_attrs'].map(id => { const e = document.getElementById(id); e.focus();
  const name = e.labels && e.labels.length ? e.labels[0].textContent.trim() : e.textContent.trim(); return { id, name, focused: document.activeElement === e }; })`);

// 4. 320px: nothing scrolls sideways, with the fields open and the result shown.
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(400);
out.narrow = await ev(`({ overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  wide: [...document.querySelectorAll('#paWiZpa *, #paZidOut *')].filter(e => e.getBoundingClientRect().right > document.documentElement.clientWidth + 1).map(e => e.tagName + '#' + e.id).slice(0, 5) })`);
await shot('zid_phone', '#paWiZpa');
out.errors = seen.errors;
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def browser(tmp_path_factory):
    shots = os.environ.get("ZID_SHOTS", "")
    fx = {"idps": IDPS, "user": USER, "result": _result()}
    return run_in_browser(tmp_path_factory.mktemp("zid"), DRIVER, json.dumps(fx), shots, timeout=180)


def test_out_of_scope_the_lookups_are_off_and_say_why(browser):
    """ASVS V4.1.3 · CWE-863 · WCAG 2.2 SC 3.3.2: without ZPA ticked the Load and Look up buttons are off and the page says a ZPA identity needs ZPA."""
    assert browser["off"]["load"] is True and browser["off"]["find"] is True and "needs ZPA ticked" in browser["off"]["hint"]


def test_the_pickers_load_idps_and_preview_groups_as_text(browser):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the IdPs and SCIM groups ZPA returns are drawn as text (a tenant string with markup runs nothing), and the request carries the scope selection."""
    pk = browser["picker"]
    assert pk["options"][0] == "Not given" and pk["options"][1] == "Okta" and "(no SCIM policy)" in pk["options"][2]
    assert "2 SCIM group(s)" in pk["groups"] and "Finance" in pk["groups"] and "<img" in pk["groups"]
    assert "Department_Okta (department)" in pk["attrHint"]
    assert pk["xss"] is False and pk["imgs"] == 0
    assert [z["action"] for z in browser["zid"]] == ["idps", "user"] and all(z["scopes"] == ["zpa"] for z in browser["zid"])


def test_the_analysis_sends_the_identity_and_shows_what_decided(browser):
    """ASVS V4.1.3 · CWE-863 · CWE-79: the start request carries the IdP, SCIM user and attributes typed; the result names the identity condition that decided, as text."""
    assert browser["start"]["zpa"] == {"idp": "216196257331281111", "user": "jane.doe@acme.example", "attributes": "Department=Finance"}
    r = browser["result"]
    assert r["heading"] == "ZPA identity" and "because SCIM group “Finance” matched" in r["text"]
    assert "Finance" in r["text"] and "unknown" in r["text"] and "<img" in r["text"]
    assert r["xss"] is False and r["imgs"] == 0
    assert browser["errors"] == []


def test_every_new_control_is_named_and_takes_focus(browser):
    """WCAG 2.2 SC 2.1.1 · SC 4.1.2 · SC 1.3.1: each ZPA identity control has an accessible name and takes keyboard focus."""
    for c in browser["a11y"]:
        assert c["name"] and c["focused"], c


def test_no_sideways_scroll_at_320px(browser):
    """WCAG 2.2 SC 1.4.10 (Reflow): at 320px the ZPA identity fields and the result never scroll the page sideways."""
    assert browser["narrow"]["overflow"] <= 0 and browser["narrow"]["wide"] == [], browser["narrow"]


# ── The ZPA builder: who the access rule allows ─────────────────────────
def _objects():
    """The builder form's read (ops_zpa.read_objects over the fake tenant), with one tenant string carrying markup."""
    import admin_ops as ao
    import ops_zpa
    import zpa_reader
    from zpa_fake import Client
    zpa_reader.PACE_SECONDS = 0.0
    ao.load_plugins()
    c = Client()
    c.tenant.add("idp", {"id": "7001", "name": "Okta", "enabled": True, "scimEnabled": True})
    c.tenant.add("saml_attribute", {"id": "7101", "name": "Department_Okta", "idpId": "7001"})
    for i, n in enumerate(["Finance", "HR", "Engineers", XSS]):
        c.tenant.add("scim_group", {"id": str(7201 + i), "name": n, "idpId": "7001"})
    res = ops_zpa.read_objects(c, ao.scope_for(["zpa"], {}), lambda m: None, None)
    return dict(res, status="done", tenant_label="acme (sample)")


OPS_DRIVER = CDP_PRELUDE + r"""
const F = JSON.parse(args[0]);
const shots = args[1];
const handlers = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } else if (m.method) handlers.forEach(h => h(m)); };
const seen = { preview: null, errors: [] };
handlers.push(m => { if (m.method === 'Runtime.exceptionThrown') seen.errors.push(m.params.exceptionDetails.text); });
handlers.push(async m => {
  if (m.method !== 'Fetch.requestPaused') return;
  const u = m.params.request.url, post = m.params.request.postData ? JSON.parse(m.params.request.postData) : {};
  let body = null;
  if (u.includes('/api/operations/objects/start')) body = { job_id: 'objjob', status: 'running' };
  else if (u.includes('/jobs/objjob')) body = { status: 'done', result: F.objects, logs: [], next: 1 };
  else if (u.includes('/api/operations/preview/start')) { seen.preview = post.operation; body = { job_id: 'prevjob', status: 'running' }; }
  else if (u.includes('/jobs/prevjob')) body = { status: 'done', result: { status: 'blocked', blockers: ['fixture'], items: [], groups: [] }, logs: [], next: 1 };
  if (!body) { await send('Fetch.continueRequest', { requestId: m.params.requestId }); return; }
  await send('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
});
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/operations/objects/start*' }, { urlPattern: '*/api/operations/preview/start*' }, { urlPattern: '*/api/dlp-packs/jobs/*' }] });
await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/operations?build=zpa_policies' });
await until(() => ev(`document.readyState === 'complete' && !!document.querySelector('input[name="opKind"][value="zpa_policies"]:checked')`), 'the builder');
await ev(`(document.getElementById('opRead').click(), 1)`);
await until(() => ev(`!!document.getElementById('zbWhoSome')`), 'the form', 20000);
await ev(`(document.getElementById('zbPrefix').value = 'pov1', document.getElementById('zbPrefix').dispatchEvent(new Event('input')), document.getElementById('zbWhoSome').click(), 1)`);
await until(() => ev(`!!document.getElementById('zbScimList')`), 'the pickers');
const out = {};
out.list = await ev(`[...document.querySelectorAll('#zbScimList li')].map(li => li.textContent.trim())`);
await ev(`(() => { const f = document.getElementById('zbScimFind'); f.value = 'fin'; f.dispatchEvent(new Event('input')); return 1; })()`);
out.filtered = await ev(`({ items: [...document.querySelectorAll('#zbScimList li')].map(li => li.textContent.trim()), focus: document.activeElement && document.activeElement.id })`);
await ev(`(() => { document.querySelector('#zbScimList input[data-scim]').click(); const a = document.getElementById('zbSamlAttr'); a.value = '7101'; a.dispatchEvent(new Event('change'));
  const v = document.getElementById('zbSamlVal'); v.value = 'Finance'; v.dispatchEvent(new Event('input')); document.getElementById('zbSamlAdd').click(); return 1; })()`);
await until(() => ev(`document.querySelectorAll('#zbSamlList li').length === 1`), 'the SAML value');
out.saml = await ev(`document.getElementById('zbSamlList').textContent.trim()`);
out.xss = await ev(`!!window.__xss || document.querySelectorAll('#opObjects img').length`);
out.names = await ev(`['zbWhoAll', 'zbWhoSome', 'zbScimFind', 'zbSamlAttr', 'zbSamlVal', 'zbSamlAdd'].map(id => { const e = document.getElementById(id); e.focus();
  return { id, focused: document.activeElement === e, name: (e.labels && e.labels.length ? e.labels[0].textContent : e.textContent).trim() }; })`);
if (shots) {
  const r = await ev(`(() => { document.querySelectorAll('.rp-bar').forEach(b => { b.style.position = 'static'; }); const e = document.getElementById('opObjects'); e.scrollIntoView({block:'start'}); const b = e.getBoundingClientRect(); return {x:b.left, y:b.top + scrollY, w:b.width, h:Math.min(b.height, 1600)}; })()`);
  await sleep(300);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 } });
  fs.writeFileSync(path.join(shots, 'zid_builder.png'), Buffer.from(s.result.data, 'base64'));
}
await ev(`(document.getElementById('opPreview').click(), 1)`);
await until(() => ev(`true`), 'x');
await sleep(1500);
out.preview = seen.preview;
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(400);
out.overflow = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
out.errors = seen.errors;
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def ops_browser(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("zidops"), OPS_DRIVER, json.dumps({"objects": _objects()}), os.environ.get("ZID_SHOTS", ""), timeout=180)


def test_the_builder_offers_the_tenants_scim_groups_and_saml_attributes_as_text(ops_browser):
    """ASVS V5.3.3 · CWE-79 · WCAG 2.2 SC 1.3.1: the access rule's pickers list the SCIM groups (filtered as you type, focus kept) and SAML attributes read from the tenant, drawn as text."""
    assert any("Finance" in x and "Okta" in x for x in ops_browser["list"]) and any("<img" in x for x in ops_browser["list"])
    assert [x.split(" Okta")[0] for x in ops_browser["filtered"]["items"]] == ["Finance"] and ops_browser["filtered"]["focus"] == "zbScimFind"
    assert ops_browser["saml"].startswith("Department_Okta = Finance") and not ops_browser["xss"]
    assert ops_browser["errors"] == []


def test_the_builder_sends_the_picks_as_ids(ops_browser):
    """ASVS V5.1.3 · CWE-20: the preview request carries the picked SCIM group and SAML value by id, nothing else."""
    op = ops_browser["preview"]
    assert op["type"] == "zpa_policies" and op["access"] is True
    assert op["access_scim_groups"] == [{"idp_id": "7001", "id": "7201"}] and op["access_saml"] == [{"id": "7101", "value": "Finance"}]


def test_the_builder_pickers_are_named_reachable_and_reflow(ops_browser):
    """WCAG 2.2 SC 2.1.1 · SC 4.1.2 · SC 1.4.10: each picker has a name and takes focus, and the form never scrolls sideways at 320px."""
    for c in ops_browser["names"]:
        assert c["name"] and c["focused"], c
    assert ops_browser["overflow"] <= 0
