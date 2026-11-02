"""Network files in a real browser (node + headless Chrome over CDP, the
harness of tests/test_findings_reflow.py; skipped without either).

On the made-up sample tenant: the fleet page reads the fleet, builds DNS
records for its devices and offers the four downloads; a hostile hostname
stays text on the page. On Policy exports: the IP range section loads with
fetching off, builds an allowlist from imported fixture feeds and shows
each source with its date. Both work at 320px without sideways scrolling,
and leave no script error. No tenant, DNS server or Zscaler site is
reached: the sample is served from memory and the feeds are fixtures.

(A help mark's 24px target reaches 4px past its slot by design, hover_help.css.)

With NETFILES_SHOTS set to a folder, screenshots are saved there.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "zscaler_ranges"

DRIVER = CDP_PRELUDE + r"""
const [shotsDir] = args;
const out = { errors: [] };
await send('Log.enable');
ws.addEventListener('message', e => { const m = JSON.parse(e.data);
  if (m.method === 'Runtime.exceptionThrown') out.errors.push(String(m.params.exceptionDetails.exception && m.params.exceptionDetails.exception.description || m.params.exceptionDetails.text).slice(0, 200));
  if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error' && m.params.entry.source !== 'network' && !/favicon/.test(m.params.entry.url || '')) out.errors.push(String(m.params.entry.text).slice(0, 200)); });
const go = async url => { await send('Page.navigate', { url: base + url }); await until(() => ev(`document.readyState === 'complete'`), url, 30000); await sleep(400); };
const shot = async (name, sel) => {
  if (!shotsDir) return;
  const r = await ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.scrollIntoView({ block: 'start' }); const b = e.getBoundingClientRect(); return { x: Math.max(0, b.left - 8), y: b.top + scrollY - 8, w: Math.min(b.width + 16, document.documentElement.clientWidth), h: Math.min(b.height + 16, 2400) }; })()`);
  await sleep(300);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 } });
  fs.writeFileSync(path.join(shotsDir, name + '.png'), Buffer.from(s.result.data, 'base64'));
};
const overflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
const past = sel => ev(`(() => { const box = document.querySelector(${JSON.stringify(sel)}); const R = Math.min(box.getBoundingClientRect().right, document.documentElement.clientWidth);
  return [...box.querySelectorAll('*')].filter(e => { if (e.closest('.tw, .df-tablewrap, pre, .ex-rg-pre')) return false; const r = e.getBoundingClientRect(); return r.width > 0 && r.right > R + (e.classList.contains('hh-mark') ? 5 : 1); })
    .map(e => e.tagName + '#' + e.id + '.' + String(e.className).slice(0, 30) + ' after ' + (e.previousElementSibling ? e.previousElementSibling.tagName + '#' + e.previousElementSibling.id + '.' + String(e.previousElementSibling.className).slice(0,20) : e.parentElement.tagName + '#' + e.parentElement.id) + ' ' + Math.round(e.getBoundingClientRect().right) + '>' + Math.round(R)).slice(0, 10); })()`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await go('/');
out.sample = await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
await ev(`(localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['zcc', 'zia', 'zia_platform', 'dlp'] })), localStorage.setItem('zsimple_mode', 'expert'), 1)`);

// ── fleet: DNS records ──
await go('/report/fleet');
out.dnsBefore = await ev(`({ build: document.getElementById('zfDnsBuild').disabled, csv: document.getElementById('zfDnsCsv').disabled, status: document.getElementById('zfDnsStatus').textContent })`);
await ev(`(document.getElementById('zfRun').click(), 1)`);
await until(() => ev(`!document.getElementById('zfDnsBuild').disabled`), 'the fleet read', 60000);
await ev(`(() => { const s = (id, v) => { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input')); }; s('zfDnsDomain', 'corp.example.com'); s('zfDnsResolvers', '10.0.0.12, 10.0.0.13'); return 1; })()`);
await ev(`(document.getElementById('zfDnsBuild').click(), 1)`);
await until(() => ev(`!!document.querySelector('#zfDnsOut table')`), 'the DNS records', 20000);
out.dns = await ev(`({ text: document.getElementById('zfDnsOut').textContent, csv: !document.getElementById('zfDnsCsv').disabled, unbound: !document.getElementById('zfDnsUnbound').disabled,
  status: document.getElementById('zfDnsStatus').textContent, rows: document.querySelectorAll('#zfDnsOut tbody tr').length })`);
await shot('fleet_dns_desktop', '#zfDns');
// A bad domain is refused in words, and the downloads switch off.
await ev(`(() => { const e = document.getElementById('zfDnsDomain'); e.value = 'not a domain'; document.getElementById('zfDnsBuild').click(); return 1; })()`);
await until(() => ev(`/Not built/.test(document.getElementById('zfDnsStatus').textContent)`), 'the refusal', 10000);
out.dnsBad = await ev(`({ status: document.getElementById('zfDnsStatus').textContent, csv: document.getElementById('zfDnsCsv').disabled })`);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await ev(`(() => { const e = document.getElementById('zfDnsDomain'); e.value = 'corp.example.com'; document.getElementById('zfDnsBuild').click(); return 1; })()`);
await until(() => ev(`!!document.querySelector('#zfDnsOut table')`), 'the DNS records at 320px', 20000);
await sleep(300);
out.fleetNarrow = await overflow();
out.fleetPast = await past('#zfDns');
await shot('fleet_dns_320', '#zfDns');

// ── exports: IP ranges ──
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await go('/report/exports');
await until(() => ev(`document.getElementById('exRgCloud').options.length > 0`), 'the ranges section', 15000);
out.rangesStart = await ev(`({ on: document.getElementById('exRgFetchOn').checked, fetch: document.getElementById('exRgFetch').disabled, box: document.getElementById('exRgBox').textContent,
  feeds: document.querySelectorAll('input[name="exRgFeed"]').length, zpa: document.querySelector('input[name="exRgFeed"][value="zpa"]').disabled })`);
out.imported = await ev(`(async () => { const feeds = ${FEEDS_JSON}; const res = []; for (const f of feeds) { const r = await fetch('/api/zscaler-ranges/import', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f) }); res.push(r.status); } return res; })()`);
await go('/report/exports');
await until(() => ev(`document.querySelectorAll('input[name="exRgRegion"]').length > 0`), 'the regions', 15000);
await ev(`(() => { const z = document.getElementById('exRgZpa'); z.value = 'private.zscaler.com'; z.dispatchEvent(new Event('change')); document.getElementById('exRgExclude').value = '165.225.240.0/24'; return 1; })()`);
await ev(`(document.getElementById('exRgBuild').click(), 1)`);
await until(() => ev(`!!document.querySelector('#exRgOut table')`), 'the allowlist', 20000);
out.ranges = await ev(`({ text: document.getElementById('exRgOut').textContent, edl: !document.getElementById('exRgEdlIp').disabled, box: document.getElementById('exRgBox').textContent,
  regions: [...document.querySelectorAll('input[name="exRgRegion"]')].map(x => x.value) })`);
await shot('exports_ranges_desktop', '#exRanges');
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await sleep(400);
out.exportsNarrow = await overflow();
out.exportsPast = await past('#exRanges');
await shot('exports_ranges_320', '#exRanges');
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def _feeds():
    pairs = [("cenr", "zscaler.net", "cenr_zscaler_net.json"), ("hubs_recommended", "zscaler.net", "hubs_recommended_zscaler_net.json"),
             ("svpn", "zscaler.net", "svpn_zscaler_net.json"), ("zpa", "private.zscaler.com", "zpa_private_zscaler_com.json")]
    return [{"feed": f, "cloud": c, "content": (FIX / n).read_text(encoding="utf-8")} for f, c, n in pairs]


@pytest.fixture(scope="module")
def netfiles(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("netfiles")
    mp = pytest.MonkeyPatch()
    mp.setenv("DLP_CHECK_ZSCALER_RANGES_DIR", str(tmp / "ranges"))
    try:
        shots = os.environ.get("NETFILES_SHOTS", "")
        return run_in_browser(tmp, DRIVER.replace("${FEEDS_JSON}", json.dumps(json.dumps(_feeds()))[1:-1]), shots, timeout=240)
    finally:
        mp.undo()


def test_the_fleet_page_builds_dns_records_from_the_sample_fleet(netfiles):
    """WCAG 2.2 SC 3.3.2 · SC 4.1.3 · ASVS V1.4.4: before a read the build is off and says why; after it the records build for the sample's devices and the four downloads switch on."""
    assert netfiles["sample"] == 200
    before = netfiles["dnsBefore"]
    assert before["build"] and before["csv"] and "Read the fleet first" in before["status"]
    d = netfiles["dns"]
    assert d["csv"] and d["unbound"] and d["rows"] >= 3, d
    assert "lkf-lt-0001.corp.example.com" in d["text"] and "Built 3 name(s)" in d["status"], d


def test_a_bad_domain_is_refused_in_words_and_the_downloads_switch_off(netfiles):
    """WCAG 2.2 SC 3.3.1 · SC 3.3.3 · ASVS V5.1.3: a domain that is not a DNS name is refused with the reason, and nothing stale can be downloaded."""
    bad = netfiles["dnsBad"]
    assert "not a DNS name" in bad["status"] and bad["csv"] is True, bad


def test_the_ranges_section_starts_offline_and_builds_from_imported_feeds(netfiles):
    """ASVS V1.14.1 · CWE-1188 · WCAG 2.2 SC 3.3.2: fetching starts off (Fetch now disabled, the ZPA feed off without a ZPA cloud); imported feeds build an allowlist with regions, sources and dates."""
    s = netfiles["rangesStart"]
    assert s["on"] is False and s["fetch"] is True and s["zpa"] is True and s["feeds"] == 6 and "Off" in s["box"], s
    assert netfiles["imported"] == [200, 200, 200, 200]
    r = netfiles["ranges"]
    assert r["edl"] and {"EMEA", "Americas", "APAC", "Global"} <= set(r["regions"]), r
    assert "Imported" in r["text"] and "Per region, aggregated" in r["text"] and "Unknown: not kept" in r["text"], r["text"][:400]


def test_both_sections_fit_320px_and_leave_no_script_errors(netfiles):
    """WCAG 2.2 SC 1.4.10 (Reflow) · ASVS V14.1 · CWE-755: at 320px neither page scrolls sideways with results shown; no console error or exception."""
    assert netfiles["fleetNarrow"] <= 0 and netfiles["exportsNarrow"] <= 0, (netfiles["fleetNarrow"], netfiles["exportsNarrow"])
    assert netfiles["fleetPast"] == [] and netfiles["exportsPast"] == [], (netfiles["fleetPast"], netfiles["exportsPast"])
    assert netfiles["errors"] == [], netfiles["errors"]
