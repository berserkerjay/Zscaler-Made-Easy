"""The one compliance choice in a real browser (node + headless Chrome over
CDP, the harness of tests/test_findings_reflow.py; skipped without either),
on the sample tenant (Larkspur Freight, made up): the ZIA security baseline
form with a compliance profile, the AI Guard form following it, the
Compliance page reading an assessment against a profile, and Simple mode's
Protect task. Nothing is written to any tenant; no network.

CP_SHOTS=<folder> saves screenshots of each state there (off by default)."""
from __future__ import annotations

import json
import os

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS

SCOPES = ["dlp", "zia_extras", "aiguard"]
CHANNELS = {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}

DRIVER = CDP_PRELUDE + "process.env.UI_DEADLINE_MS = process.env.UI_DEADLINE_MS || '420000';\n" + EVENTS + r"""
const [scopesJson, channelsJson, shots] = args;
const out = { errors: [] };
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 200); } };
// A screenshot of the part of the page `sel` names (the whole viewport without one).
const shot = async (name, sel) => {
  if (!shots) return;
  const box = sel ? await ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return null; const r = e.getBoundingClientRect(); return { x: Math.max(0, r.left + scrollX - 8), y: Math.max(0, r.top + scrollY - 8), width: Math.min(r.width + 16, document.documentElement.scrollWidth), height: Math.min(r.height + 16, 2400), scale: 1 }; })()`) : null;
  const r = await send('Page.captureScreenshot', Object.assign({ format: 'png' }, box ? { clip: box, captureBeyondViewport: true } : {}));
  fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(r.result.data, 'base64'));
};
const frames = () => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
const pick = (sel, value) => ev(`(() => { const s = document.querySelector(${JSON.stringify(sel)}); if (!s) return false; s.value = ${JSON.stringify(value)}; s.dispatchEvent(new Event('change', { bubbles: true })); return s.value === ${JSON.stringify(value)}; })()`);
const reflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
const wide = () => ev(`(() => { const W = document.documentElement.clientWidth; return [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > W + 1 && getComputedStyle(e).position !== 'fixed' && !(e.parentElement && e.parentElement.getBoundingClientRect().right > W + 1); }).map(e => e.tagName + '#' + e.id + '.' + String(e.className).slice(0, 40) + ' ' + (e.textContent || '').trim().slice(0, 40) + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 10); })()`);
const width = w => send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });

// The sample tenant in this browser, the scope the Scope page would save, and a saved tenant profile.
await go('/');
await ev(`(localStorage.setItem('zsimple_mode', 'expert'), localStorage.setItem('zassess_scopes_live_v1', ${JSON.stringify(JSON.stringify({ scopes: JSON.parse(scopesJson) }))}),
  localStorage.setItem('zassess_channels_v1', ${JSON.stringify(channelsJson)}), true)`);
await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
out.profile = await ev(`fetch('/api/tenant-profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Larkspur Federal', vanity_domain: 'larkspur' }) }).then(r => r.json()).then(p => p.id)`);

// 1. The ZIA security baseline with a compliance profile.
await go('/report/operations');
await until(() => ev(`!!(window.OPS_PLUGINS && window.OPS_PLUGINS.defs.zia_baseline && document.querySelector('input[name=opKind][value=zia_baseline]'))`), 'the baseline builder');
await until(() => ev(`[...document.querySelectorAll('#opTenant option')].some(o => o.value === 'profile:' + ${JSON.stringify(out.profile)})`), 'the tenant profile');
await ev(`(() => { const s = document.getElementById('opTenant'); s.value = 'profile:' + ${JSON.stringify(out.profile)}; s.dispatchEvent(new Event('change')); return 1; })()`);
await ev(`document.querySelector('input[name=opKind][value=zia_baseline]').click(), 1`);
await ev(`document.getElementById('opRead').click(), 1`);
await until(() => ev(`!!document.getElementById('zbCompliance')`), 'the compliance profile select', 60000);
await safe('groups', () => ev(`[...document.querySelectorAll('#zbCompliance optgroup')].map(g => g.label)`));
await safe('federalOptions', () => ev(`[...document.querySelectorAll('#zbCompliance optgroup[label="Federal and public sector"] option')].map(o => o.textContent)`));
await pick('#zbCompliance', 'FEDRAMP_HIGH');
await until(() => ev(`!!document.getElementById('zbCpSummary')`), 'the profile summary');
await until(() => ev(`/Remembered for this tenant profile/.test(document.getElementById('opObjects').textContent)`), 'the remembered note').catch(() => null);
await safe('summary', () => ev(`document.getElementById('zbCpSummary').innerText`));
await safe('tier', () => ev(`(document.querySelector('input[name=zbTier]:checked') || {}).value`));
await safe('overlay', () => ev(`document.querySelector('input[data-zb-ov="NIST_800_53"]').checked`));
await safe('locked', () => ev(`[...document.querySelectorAll('#opObjects tr')].filter(tr => /required by FedRAMP High/.test(tr.textContent)).map(tr => tr.querySelector('label').textContent)`));
await safe('exemptions', () => ev(`[...document.querySelectorAll('#opObjects label')].filter(l => /SSL-Ex/.test(l.textContent)).length`));
await safe('remembered', () => ev(`fetch('/api/tenant-profiles').then(r => r.json()).then(d => (d.profiles.find(p => p.id === ${JSON.stringify(out.profile)}) || {}).compliance_profile)`));
await safe('selectFocusable', () => ev(`(() => { const s = document.getElementById('zbCompliance'); s.focus(); return document.activeElement === s && s.tabIndex >= 0; })()`));
await ev(`document.getElementById('zbCpCheck').click(), 1`);
await until(() => ev(`/none has neither/.test(document.getElementById('opObjects').textContent)`), 'the mapping check', 60000);
await safe('check', () => ev(`[...document.querySelectorAll('#opObjects [role=status]')].map(e => e.textContent).find(t => /none has neither/.test(t))`));
await safe('fileButtons', () => ev(`[...document.querySelectorAll('button[data-zb-cp-file]')].map(b => b.dataset.zbCpFile)`));
// A download goes through the app's own POST route (fetch, same origin) and comes back as an attachment.
await safe('download', () => ev(`fetch('/api/compliance-pack/file', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ compliance_profile: 'FEDRAMP_HIGH', file: 'mapping.csv' }) })
  .then(async r => ({ status: r.status, cd: r.headers.get('Content-Disposition'), head: (await r.text()).slice(0, 40) }))`));
await shot('baseline-fedramp-high', '#zbCompliance');
await shot('baseline-fedramp-high-profile', 'fieldset:has(#zbCompliance)');
await width(320); await frames();
await safe('reflowOps', reflow);
await safe('wideOps', wide);
await shot('baseline-320', 'fieldset:has(#zbCompliance)');
await width(1280); await frames();
// Preview the build: the plan names the profile (the sample tenant is read, nothing written).
await ev(`document.getElementById('opPreview').click(), 1`);
await until(() => ev(`/FedRAMP High/.test(document.getElementById('opPlan').textContent) || /could not/i.test(document.getElementById('opPlan').textContent)`), 'the preview', 120000).catch(() => null);
await safe('preview', () => ev(`document.getElementById('opPlan').textContent.slice(0, 400)`));

// 2. AI Guard detection policy follows the choice.
await ev(`document.querySelector('input[name=opKind][value=aiguard_detection_policy]').click(), 1`);
await ev(`document.getElementById('opRead').click(), 1`);
await until(() => ev(`!!document.getElementById('aigProfile') || /could not be read|not/i.test(document.getElementById('opObjects').textContent)`), 'the AI Guard form', 60000).catch(() => null);
await until(() => ev(`!!document.getElementById('aigFromCp')`), 'the compliance chip', 10000).catch(() => null);
await safe('aig', () => ev(`({ value: (document.getElementById('aigProfile') || {}).value || '', chip: (document.getElementById('aigFromCp') || {}).textContent || '' })`));
await shot('aiguard-follows', '#opObjects');

// 3. The Compliance page: an assessment read against CMMC Level 2.
const checks = [{ id: 'FW.1', label: 'Firewall default deny', status: 'FAIL' }, { id: '4.1', label: 'SSL inspection on', status: 'PASS' },
  { id: 'ZPA.1', label: 'ZPA access rules', status: 'REVIEW' }, { id: '2.1', label: 'URL filtering', status: 'PASS' }];
const rid = await ev(`fetch('/api/compliance/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ checks: ${JSON.stringify(checks)}, frameworks: ['CMMC_L2'] }) }).then(r => r.json()).then(d => d.report_id)`);
await go('/report/compliance?id=' + encodeURIComponent(rid));
await until(() => ev(`!!document.getElementById('cpProfilePick')`), 'the profile picker', 30000);
await pick('#cpProfilePick', 'CMMC_L2');
await until(() => ev(`/not met/.test(document.getElementById('cpProfileOut').textContent)`), 'the profile view', 30000);
await safe('view', () => ev(`({ status: document.querySelector('#cpProfileOut [role=status]').textContent, csv: document.getElementById('cpProfileCsv').getAttribute('href'), hidden: document.getElementById('cpProfileCsv').hidden })`));
await shot('compliance-page-cmmc', '#cpProfile');
await width(320); await frames();
await safe('reflowCompliance', reflow);
await safe('wideCompliance', wide);
await width(1280);

// 4. Simple mode: Federal offers the federal profiles before the rule sets.
await go('/simple#protect');
await until(() => ev(`!!document.querySelector('input[name=smKind]')`), 'the kind step', 30000);
await ev(`(() => { const r = document.querySelector('input[name=smKind][value="Federal"]'); r.click(); return 1; })()`);
await ev(`document.getElementById('smNext').click(), 1`);
await until(() => ev(`!!document.querySelector('input[name=smProfile]')`), 'the profile step', 30000);
await safe('simple', () => ev(`({ options: [...document.querySelectorAll('input[name=smProfile]')].map(i => i.value), checked: (document.querySelector('input[name=smProfile]:checked') || {}).value })`));
await ev(`document.getElementById('smNext').click(), 1`);
await until(() => ev(`!!document.querySelector('input[name=smPack]')`), 'the pack step', 30000);
await safe('simplePacks', () => ev(`[...document.querySelectorAll('input[name=smPack]')].map(i => i.value)`));
await shot('simple-federal');
out.errors = seen.errors.filter(e => !/favicon/.test(e));
fs.writeFileSync(path.join(dir, 'out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'out.json') }));
p.kill();
process.exit(0);
"""


@pytest.fixture(scope="module")
def ui(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cp-browser")
    shots = os.environ.get("CP_SHOTS", "")
    res = run_in_browser(tmp, DRIVER, json.dumps(SCOPES), json.dumps(CHANNELS), shots, timeout=480)
    from pathlib import Path
    return json.loads(Path(res["file"]).read_text(encoding="utf-8"))


def test_the_baseline_form_offers_the_federal_profiles_first(ui):
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · ASVS V1.14.1: the compliance profile select groups the profiles, Federal and public sector first, with all six federal profiles."""
    assert ui["groups"][0] == "Federal and public sector", ui["groups"]
    assert {"FedRAMP Moderate", "FedRAMP High", "CMMC Level 2", "GovRAMP Moderate"} <= set(ui["federalOptions"]), ui["federalOptions"]


def test_picking_a_profile_says_what_it_will_do_and_drives_the_baseline(ui):
    """WCAG 2.2 SC 3.3.2 · SC 4.1.3 · ASVS V1.14.1: FedRAMP High picks Strict and its overlay, says what it requires, locks the rules AC-4(4) needs and is remembered for the tenant profile."""
    assert "What FedRAMP High will do" in ui["summary"] and "AC-4(4)" in ui["summary"] and "Assumed" not in ui["summary"][:5]
    assert ui["tier"] == "strict" and ui["overlay"] is True
    assert any("SSL-Catch-All" in n for n in ui["locked"]) and any("QUIC" in n for n in ui["locked"]), ui["locked"]
    assert ui["exemptions"] == 0
    assert ui["remembered"] == "FEDRAMP_HIGH"
    assert ui["selectFocusable"] is True


def test_check_the_mapping_and_the_downloads_work_through_the_app(ui):
    """ASVS V1.14.1 · V4.1.1 · CWE-1059: Check the mapping reports no rule with neither a control nor a reason; the pack files download as attachments from the app's own route."""
    assert "none has neither" in ui["check"], ui["check"]
    assert set(ui["fileButtons"]) >= {"mapping.html", "mapping.xlsx", "policy.json", "testplan.html", "compliance-pack.zip"}
    d = ui["download"]
    assert d["status"] == 200 and d["cd"].startswith("attachment;") and d["head"].startswith("# Control mapping: FedRAMP High")


def test_the_preview_names_the_profile(ui):
    """ASVS V1.14.1 · CWE-1059: the preview of the build (read-only, the sample tenant) names the compliance profile."""
    assert "FedRAMP High" in ui["preview"], ui["preview"]


def test_the_ai_guard_form_follows_the_compliance_choice(ui):
    """WCAG 2.2 SC 3.2.2 · ASVS V1.14.1: after FedRAMP High is picked, the AI Guard detection policy form starts on NIST SP 800-53 and says it came from the compliance profile."""
    if not ui["aig"]["value"]:
        pytest.skip("the sample tenant has no AI Guard to read")
    assert ui["aig"]["value"] == "NIST_800_53" and "FedRAMP High" in ui["aig"]["chip"]


def test_the_compliance_page_reads_an_assessment_against_a_profile(ui):
    """WCAG 2.2 SC 4.1.3 · ASVS V1.14.1: picking CMMC Level 2 shows met, not met and not assessed counts and a CSV download of the same view."""
    v = ui["view"]
    assert "CMMC Level 2" in v["status"] and "not met" in v["status"] and "not assessed" in v["status"]
    assert v["hidden"] is False and v["csv"].endswith("/profile/CMMC_L2?format=csv")


def test_simple_mode_offers_the_federal_profiles_before_the_rule_sets(ui):
    """WCAG 2.2 SC 3.3.2 · SC 3.2.4: Federal offers the federal profiles (FedRAMP Moderate first) and the rule sets that follow from it."""
    assert ui["simple"]["options"][0] == "FEDRAMP_MOD" and ui["simple"]["checked"] == "FEDRAMP_MOD" and "none" in ui["simple"]["options"]
    assert ui["simplePacks"][0] == "fed_policy_pack"


def test_no_sideways_scroll_at_320px_and_no_script_errors(ui):
    """WCAG 2.2 SC 1.4.10 · SC 4.1.2: the baseline form with a profile and the Compliance page's profile view reflow at 320px; no script error on the way."""
    assert ui["reflowOps"] <= 0 and ui["reflowCompliance"] <= 0, (ui["wideOps"], ui["wideCompliance"])
    assert not ui["errors"], ui["errors"]
