"""The fix flow in a real browser (headless Chrome over CDP, as
tests/test_findings_reflow.py drives it): the real app serves the real Bulk
changes page; the Fix selected hand-off, the object reads and the preview
answer with fixtures through the CDP Fetch domain, so no tenant is read and
nothing is written.

Checked: a hand-off holding only rows ZPA carries opens "ZPA segment
domains" (not a ZIA operation) with the row's segment and domains picked,
and its preview asks to take them out of that segment; a hand-off with URL
filtering rows opens "Fix rows from Test a list" with a custom URL category
and a new rule placed above the rule that decided the rows; the ZPA
builder's "Place it above" goes into the preview as the rule's id; a hand-off
with two ZPA segments offers both: a row to allow opens ZPA policy rules with
the segment that already holds it and the rule that denied it picked (an
access rule for that existing segment), and picking the other segment, a row
to block, opens ZPA segment domains for it; every new control is labelled
and reachable by keyboard; nothing scrolls sideways at 320px. Skips without
node or Chrome.
"""
from __future__ import annotations

import json

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

ZPA_FIX = "a" * 24
URL_FIX = "b" * 24
MULTI_FIX = "c" * 24


def _fixtures() -> dict:
    """The page's inputs, built by the same functions the routes use, over the test fakes."""
    import admin_ops as ao
    import ops_list_fix as lf
    import ops_zpa
    import zpa_reader
    import test_admin_ops as tao
    import test_ops_list_fix as tlf
    from zpa_fake import Client
    zpa_reader.PACE_SECONDS = 0.0
    ao.load_plugins()
    segs = ao.read_objects(tao.Tenant(), "zpa_segments", tao.FULL_SCOPE)
    lfo = ao.read_objects(tlf.Tenant(), lf.FAMILY, tlf.PLATFORM)
    c = Client()
    deny = c.tenant.add("rule:access", {"name": "Deny contractors", "action": "DENY", "ruleOrder": "1"})
    c.tenant.add("rule:access", {"name": "Allow staff", "action": "ALLOW", "ruleOrder": "2"})
    c.tenant.add("rule:access", {"name": "Default_Rule", "action": "DENY", "ruleOrder": "3", "defaultRule": True})
    c.tenant.add("segment", {"name": "Payroll", "enabled": True, "domainNames": ["pay.corp.example"], "tcpPortRanges": ["443", "443"]})
    hr = c.tenant.add("segment", {"name": "HR apps", "enabled": True, "domainNames": ["hr.corp.example"], "tcpPortRanges": ["443", "443"]})
    zb = ops_zpa.read_objects(c, ao.scope_for(["zpa"], {}), lambda m: None, None)
    done = lambda r: dict(r, status="done", tenant_label="acme (fixture)")  # noqa: E731
    base = {"excluded": [], "over_limit": 0, "note": "From the Path analyzer's Test a list view."}
    return {
        "families": {"zpa_segments": done(segs), lf.FAMILY: done(lfo), ops_zpa.FAMILY: done(zb)},
        "fixes": {
            ZPA_FIX: dict(base, urls=[], fixes=[], purpose="block",
                          zpa=[{"segment": "Intranet", "purpose": "block", "domains": ["hr.corp.example"], "rows": [5], "decided_by": ["Allow staff"],
                                "recommendation": "Take it out of the segment so ZIA's policy applies."}],
                          rows=[{"row": 5, "target": "hr.corp.example", "expected": "BLOCK", "result": "allowed", "rule": "Allow staff", "area": "ZPA"}]),
            URL_FIX: dict(base, urls=["friends.example"], purpose="allow", zpa=[],
                          fixes=[{"area": "url", "area_label": "URL filtering", "purpose": "allow", "rows": [1],
                                  "destinations": [{"value": "friends.example", "rows": [1]}], "decided_by": ["Block social"],
                                  "recommendation": "Add it to a custom URL category used by an Allow rule above that rule."}],
                          rows=[{"row": 1, "target": "friends.example", "expected": "ALLOW", "result": "blocked", "rule": "Block social", "area": "URL"}]),
            MULTI_FIX: dict(base, urls=[], fixes=[], purpose="allow",
                            zpa=[{"segment": "HR apps", "purpose": "allow", "domains": ["hr.corp.example"], "rows": [7], "decided_by": ["Deny contractors"],
                                  "recommendation": "An access rule above the rule that denies it."},
                                 {"segment": "Intranet", "purpose": "block", "domains": ["hr.corp.example"], "rows": [8], "decided_by": ["Allow staff"],
                                  "recommendation": "Take it out of the segment so ZIA's policy applies."}],
                            rows=[]),
        },
        "deny": deny["id"], "hr": hr["id"],
    }


DRIVER = CDP_PRELUDE + r"""
const F = JSON.parse(args[0]);
const handlers = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } else if (m.method) handlers.forEach(h => h(m)); };
const seen = { previews: [], families: [], errors: [] };
handlers.push(m => { if (m.method === 'Runtime.exceptionThrown') seen.errors.push(m.params.exceptionDetails.text); });
handlers.push(async m => {
  if (m.method !== 'Fetch.requestPaused') return;
  const u = m.params.request.url, post = m.params.request.postData ? JSON.parse(m.params.request.postData) : {};
  let body = null;
  const fix = u.match(/\/api\/bulk-test\/fix\/([a-f0-9]{24})$/);
  if (fix) body = F.fixes[fix[1]];
  else if (u.includes('/api/operations/objects/start')) { seen.families.push(post.family); body = { job_id: 'obj-' + post.family, status: 'running' }; }
  else if (u.includes('/jobs/obj-')) body = { status: 'done', result: F.families[decodeURIComponent(u.split('/jobs/obj-')[1].split('?')[0])], logs: [], next: 1 };
  else if (u.includes('/api/operations/preview/start')) { seen.previews.push(post.operation); body = { job_id: 'prevjob', status: 'running' }; }
  else if (u.includes('/jobs/prevjob')) body = { status: 'done', result: { status: 'blocked', blockers: ['fixture'], items: [], groups: [] }, logs: [], next: 1 };
  if (!body) { await send('Fetch.continueRequest', { requestId: m.params.requestId }); return; }
  await send('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
});
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/bulk-test/fix/*' }, { urlPattern: '*/api/operations/objects/start*' }, { urlPattern: '*/api/operations/preview/start*' }, { urlPattern: '*/api/dlp-packs/jobs/*' }] });
await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
const out = {};
// The operation the page acts on (its state, which a browser-restored radio tick alone does not change), when its radio is ticked too.
const picked = `(((window.OPS_PLUGINS || {}).state || {}).kind === ((document.querySelector('input[name="opKind"]:checked') || {}).value) ? window.OPS_PLUGINS.state.kind : '')`;
// Page.navigate returns before the old page is gone: every wait names the new address too, so it never reads the page before.
const at = q => `location.href.includes(${JSON.stringify(q)}) && document.readyState === 'complete'`;
const named = ids => ev(`${JSON.stringify(ids)}.map(id => { const e = document.getElementById(id); if (!e) return { id, missing: true }; e.focus();
  return { id, focused: document.activeElement === e, name: ((e.labels && e.labels.length ? e.labels[0].textContent : '') || e.getAttribute('aria-label') || '').trim() }; })`);
async function preview(n) {
  await ev(`(document.getElementById('opPreview').disabled = false, document.getElementById('opPreview').click(), 1)`);
  await until(async () => seen.previews.length >= n, 'the preview request');
  return seen.previews[n - 1];
}

// 1. Rows ZPA carries, nothing else: the ZPA segment change, never a ZIA one.
await send('Page.navigate', { url: base + '/report/operations?fix=' + Object.keys(F.fixes)[0] });
await until(() => ev(`${at('fix=' + Object.keys(F.fixes)[0])} && ${picked} === 'zpa_domains'`), 'the ZPA operation picked', 60000);
out.zpaKind = await ev(picked);
await ev(`(document.getElementById('opRead').click(), 1)`);
await until(() => ev(`!!document.getElementById('opZAct')`), 'the ZPA form', 60000);
out.zpaForm = await ev(`({ act: document.getElementById('opZAct').value, src: document.getElementById('opZSrc').value,
  picked: [...document.querySelectorAll('input[data-d]:checked')].map(c => c.dataset.d),
  card: (document.querySelector('#opObjects .bp-card.info') || {}).textContent || '' })`);
out.zpaPreview = await preview(1);
await ev(`(() => { const a = document.getElementById('opZAct'); a.value = 'add'; a.dispatchEvent(new Event('change')); return 1; })()`);
await until(() => ev(`!!document.getElementById('opZAdd')`), 'the typed domains');
out.zpaAdd = await ev(`document.getElementById('opZAdd').value`);
out.zpaNames = await named(['opZAct', 'opZTgt', 'opZAdd']);

// 2. URL filtering rows: Fix rows from Test a list, with the category and a rule above the deciding rule.
await send('Page.navigate', { url: base + '/report/operations?fix=' + Object.keys(F.fixes)[1] });
await until(() => ev(`${at('fix=' + Object.keys(F.fixes)[1])} && ${picked} === 'list_fix'`), 'the list fix picked', 60000);
out.urlKind = await ev(picked);
await ev(`(document.getElementById('opRead').click(), 1)`);
await until(() => ev(`!!document.getElementById('lfCat0')`), 'the URL section', 60000);
out.urlForm = await ev(`({ cat: document.getElementById('lfCat0').value, rule: document.getElementById('lfRule0').value,
  above: document.getElementById('lfAbove0').value, cats: [...document.getElementById('lfCat0').options].map(o => o.textContent.trim()) })`);
out.urlPreview = await preview(2);
out.urlNames = await named(['lfCat0', 'lfCatName0', 'lfRule0', 'lfAbove0']);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
out.urlOverflow = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

// 3. The ZPA builder: Place it above.
await send('Page.navigate', { url: base + '/report/operations?build=zpa_policies' });
await until(() => ev(`${at('build=zpa_policies')} && ${picked} === 'zpa_policies'`), 'the builder', 60000);
await ev(`(document.getElementById('opRead').click(), 1)`);
await until(() => ev(`!!document.getElementById('zbAbove')`), 'the policy form', 60000);
out.aboveOptions = await ev(`[...document.getElementById('zbAbove').options].map(o => o.textContent.trim())`);
await ev(`(() => { const p = document.getElementById('zbPrefix'); p.value = 'pov1'; p.dispatchEvent(new Event('input'));
  const a = document.getElementById('zbAbove'); a.value = ${JSON.stringify(F.deny)}; a.dispatchEvent(new Event('change')); return 1; })()`);
out.builderPreview = await preview(3);
out.builderNames = await named(['zbAbove']);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
out.builderOverflow = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

// 4. Two ZPA segments: a row to allow (an access rule for the segment that holds it), then the other segment, a row to block.
await send('Page.navigate', { url: base + '/report/operations?fix=' + Object.keys(F.fixes)[2] });
await until(() => ev(`${at('fix=' + Object.keys(F.fixes)[2])} && ${picked} === 'zpa_policies'`), 'ZPA policy rules picked for a row to allow', 60000);
out.multiKind = await ev(picked);
await ev(`(document.getElementById('opRead').click(), 1)`);
await until(() => ev(`!!document.getElementById('zbSeg')`), 'the existing segment', 60000);
out.multiForm = await ev(`({ seg: document.getElementById('zbSeg').value, above: document.getElementById('zbAbove').value,
  existing: document.getElementById('zbAppsExisting').checked, prefix: document.getElementById('zbPrefix').value,
  timeoutShown: !!document.getElementById('zbTimeout'), hint: document.getElementById('zbSegHint').textContent,
  picker: [...document.getElementById('opZHand').options].map(o => o.textContent.trim()) })`);
out.multiPreview = await preview(4);
out.multiNames = await named(['opZHand', 'zbAppsExisting', 'zbSeg']);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
out.multiOverflow = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await ev(`(() => { const h = document.getElementById('opZHand'); h.value = '1'; h.dispatchEvent(new Event('change')); return 1; })()`);
await until(() => ev(`${picked} === 'zpa_domains'`), 'ZPA segment domains picked for the second segment');
out.secondKind = await ev(picked);
// Read clicked until it starts: the page ignores it while the preview's job is still finishing.
await until(() => ev(`!!document.getElementById('opZAct') || (document.getElementById('opRead').click(), false)`), 'the second segment form', 60000);
out.secondForm = await ev(`({ act: document.getElementById('opZAct').value, src: document.getElementById('opZSrc').value, hand: document.getElementById('opZHand').value,
  picked: [...document.querySelectorAll('input[data-d]:checked')].map(c => c.dataset.d) })`);
out.families = seen.families;
out.errors = seen.errors;
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def flow(tmp_path_factory):
    f = _fixtures()
    return dict(run_in_browser(tmp_path_factory.mktemp("fixflow"), DRIVER, json.dumps(f), timeout=240), deny=f["deny"], hr=f["hr"])


def test_zpa_rows_open_the_zpa_segment_change_not_a_zia_one(flow):
    """ASVS V4.1.1 · CWE-841 · WCAG 2.2 SC 3.2.2: a hand-off of rows ZPA carries picks ZPA segment domains, with the row's segment and domain picked; its preview takes the domain out of that segment."""
    assert flow["zpaKind"] == "zpa_domains" and flow["families"][0] == "zpa_segments"
    assert flow["zpaForm"]["act"] == "remove" and flow["zpaForm"]["src"] == "s1" and flow["zpaForm"]["picked"] == ["hr.corp.example"]
    assert "Intranet" in flow["zpaForm"]["card"] and "row" in flow["zpaForm"]["card"].lower()
    assert flow["zpaPreview"] == {"type": "zpa_domains", "action": "remove", "source": "s1", "domains": ["hr.corp.example"]}
    assert flow["zpaAdd"] == "hr.corp.example", "Add typed domains starts from the hand-off's domains"


def test_url_rows_open_the_list_fix_with_a_category_and_a_rule_above_the_deciding_rule(flow):
    """ASVS V1.4.1 · CWE-1059 · CWE-1188: a hand-off of URL filtering rows picks Fix rows from Test a list; the preview asks for a new custom URL category and a new rule, disabled, above the rule that decided the rows."""
    assert flow["urlKind"] == "list_fix"
    assert flow["urlForm"]["cat"] == "new" and flow["urlForm"]["rule"] == "new" and flow["urlForm"]["above"] == "82"
    assert any("Partners" in c for c in flow["urlForm"]["cats"])
    fx = flow["urlPreview"]["fixes"][0]
    assert flow["urlPreview"]["type"] == "list_fix" and fx["area"] == "url" and fx["purpose"] == "allow" and fx["action"] == "add"
    assert fx["destinations"] == [{"value": "friends.example", "rows": [1]}] and fx["decided_by"] == ["Block social"]
    assert fx["category"]["new"].startswith("Fix Allow") and fx["rule"]["new"]["above"] == "82" and fx["rule"]["new"]["enabled"] is False


def test_the_builder_sends_place_it_above_as_the_rules_id(flow):
    """ASVS V5.1.3 · CWE-20: the access policy is offered top first without the Default rule, and the picked rule goes into the preview by id."""
    assert [o.split(". ", 1)[-1].split(" (")[0] for o in flow["aboveOptions"]] == ["Last", "Deny contractors", "Allow staff"]
    assert flow["builderPreview"]["type"] == "zpa_policies" and flow["builderPreview"]["access_above"] == flow["deny"]


def test_a_zpa_row_to_allow_opens_an_access_rule_for_the_segment_that_already_holds_it(flow):
    """ASVS V4.1.1 · CWE-841 · CWE-1188 · WCAG 2.2 SC 3.2.2: a row ZPA denies opens ZPA policy rules, not Add typed domains; the existing segment holding it and the rule that denied it are picked, and the preview asks for an access rule over that segment alone."""
    assert flow["multiKind"] == "zpa_policies"
    f = flow["multiForm"]
    assert f["existing"] is True and f["seg"] == flow["hr"] and f["above"] == flow["deny"] and f["prefix"] == "fix"
    assert f["timeoutShown"] is False and "HR apps" in f["hint"] and "ALLOW ACCESS NOW" in f["hint"]
    pv = flow["multiPreview"]
    assert pv["type"] == "zpa_policies" and pv["access_segments"] == [flow["hr"]] and pv["access_above"] == flow["deny"]
    assert pv["access"] is True and pv["timeout"] is False and pv["inspection"] is False and pv["isolation_profile_id"] == ""


def test_every_segment_of_a_multi_segment_hand_off_can_be_picked(flow):
    """ASVS V4.1.1 · CWE-841 · WCAG 2.2 SC 3.2.2: a hand-off with two ZPA segments lists both; picking the second (a row to block) opens ZPA segment domains with that segment and its domain picked."""
    assert len(flow["multiForm"]["picker"]) == 2 and "HR apps" in flow["multiForm"]["picker"][0] and "to block" in flow["multiForm"]["picker"][1]
    assert flow["secondKind"] == "zpa_domains"
    assert flow["secondForm"] == {"act": "remove", "src": "s1", "hand": "1", "picked": ["hr.corp.example"]}


def test_the_new_controls_are_named_reachable_and_reflow(flow):
    """WCAG 2.2 SC 2.1.1 · SC 4.1.2 · SC 1.4.10: each new control has a name and takes focus; the page never scrolls sideways at 320px; no script error."""
    for c in flow["zpaNames"] + flow["urlNames"] + flow["builderNames"] + flow["multiNames"]:
        assert not c.get("missing") and c["name"] and c["focused"], c
    assert flow["urlOverflow"] <= 0 and flow["builderOverflow"] <= 0 and flow["multiOverflow"] <= 0
    assert flow["errors"] == []
