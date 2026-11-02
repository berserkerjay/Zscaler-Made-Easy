"""The ZDX panel of the Path analyzer and the new Client Connector fleet
sections, in a real browser on the made-up sample tenant (Larkspur Freight):
the panel loads the ZDX applications, picks the one matching the destination
and draws the measured cloud path; the fleet page shows one device's details
and the disable-reason counts; nothing names a person or a device; every new
control is reachable by keyboard; nothing scrolls sideways at 320px; the
words keep AA contrast. Uses the node + headless Chrome harness of
tests/test_findings_reflow.py (skipped without either). No tenant is read."""
from __future__ import annotations

import json

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS

DRIVER = CDP_PRELUDE + EVENTS + r"""
const out = {};
await go('/');
// The sample tenant in this browser, and the Scope page's ticks as the tools read them.
if (!await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.ok)`)) throw new Error('the sample tenant did not open');
await ev(`(localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['zdx', 'zcc', 'zidentity'] })), true)`);

await go('/report/path'); await settle('/report/path');
await ev(`(document.getElementById('paDest').value = 'https://billing.larkspur-freight.example/invoices', document.getElementById('zdxCp').open = true, true)`);
await ev(`(document.getElementById('zdxCpLoad').click(), true)`);
await until(() => ev(`!document.getElementById('zdxCpApp').disabled`), 'the ZDX applications');
out.picked = await ev(`document.getElementById('zdxCpApp').selectedOptions[0].textContent`);
await ev(`(document.getElementById('zdxCpShow').click(), true)`);
await until(() => ev(`!!document.querySelector('#zdxCpOut table')`), 'the cloud path table');
out.path = await ev(`(() => { const o = document.getElementById('zdxCpOut'); return { text: o.textContent, rows: o.querySelectorAll('tbody tr').length, warn: o.querySelectorAll('tbody tr.st-warn').length }; })()`);
// Without the typed phrase nothing starts (checked in the page, before any request).
await ev(`(document.getElementById('zdxRcaWho').value = 'Jane Doe', document.getElementById('zdxRcaStart').click(), true)`);
out.noPhrase = await ev(`document.getElementById('zdxRcaOut').textContent`);
// Keyboard: every new control takes focus.
out.focus = await ev(`['zdxCpLoad', 'zdxCpApp', 'zdxCpShow', 'zdxRcaDev', 'zdxRcaHours', 'zdxRcaWho', 'zdxRcaPhrase', 'zdxRcaStart'].map(id => { const e = document.getElementById(id); e.focus(); return document.activeElement === e; })`);
// AA contrast of the panel's words against what is behind them.
out.contrast = await ev(`(() => {
  const rgba = s => { const m = String(s).match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const v = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const behind = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let c = { r: 255, g: 255, b: 255, a: 1 }; const root = rgba(getComputedStyle(document.documentElement).backgroundColor); if (root && root.a > 0) c = over(root, c); for (const n of chain.reverse()) { const b = rgba(getComputedStyle(n).backgroundColor); if (b && b.a > 0) c = over(b, c); } return c; };
  return [...document.querySelectorAll('#zdxCp summary, #zdxCp .df-hint, #zdxCp .lbl, #zdxCpOut td, #zdxCpOut th')].filter(e => e.getClientRects().length).map(e => { const bg = behind(e); return Math.round(ratio(over(rgba(getComputedStyle(e).color), bg), bg) * 100) / 100; });
})()`);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await settle('320px');
out.narrowPath = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);

await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await go('/report/fleet'); await settle('/report/fleet');
await ev(`(document.getElementById('zfDevUdid').value = 'LKF-WIN-0003', document.getElementById('zfDevShow').click(), true)`);
await until(() => ev(`!!document.querySelector('#zfDevOut table')`), 'the device details');
out.device = await ev(`document.getElementById('zfDevOut').textContent`);
await ev(`(document.getElementById('zfDisShow').click(), true)`);
await until(() => ev(`!!document.querySelector('#zfDisOut table')`), 'the disable-reason counts');
out.disable = await ev(`document.getElementById('zfDisOut').textContent`);
out.fleetFocus = await ev(`['zfDevUdid', 'zfDevShow', 'zfDisShow', 'zfDisCsv'].map(id => { const e = document.getElementById(id); e.focus(); return document.activeElement === e; })`);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await settle('320px fleet');
out.narrowFleet = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
out.writes = await ev(`fetch('/api/offline/status').then(r => r.json()).then(s => s.changes)`);
out.errors = seen.errors.splice(0);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def tour(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("w8-zdx-zcc"), DRIVER, timeout=240)


def test_the_zdx_panel_draws_the_measured_cloud_path_without_naming_a_device(tour):
    """ASVS V8.3.4 · CWE-359 · WCAG 2.2 SC 1.3.1: on the sample tenant the panel picks the application matching the destination and draws three legs; the lossy leg is marked; no device, person or private address is shown."""
    # Assert
    assert tour["picked"].startswith("Freight billing")
    assert tour["path"]["rows"] == 3 and tour["path"]["warn"] >= 1 and "slowest leg" in tour["path"]["text"]
    for leak in ("LKF-", "avery", "192.168.", "00:00:5e"):
        assert leak not in tour["path"]["text"], leak


def test_the_score_analysis_is_not_started_without_the_typed_phrase(tour):
    """ASVS V11.1.1 · CWE-841 · WCAG 2.2 SC 3.3.1: without START ANALYSIS the page says what to type and sends nothing; the sample tenant counts no change."""
    # Assert
    assert "Type START ANALYSIS" in tour["noPhrase"] and tour["writes"] == 0


def test_the_fleet_page_shows_device_details_and_counts_without_names(tour):
    """ASVS V8.3.4 · ASVS V8.1.1 · CWE-200 · CWE-359: the device details call out what needs a look with identifiers hidden; the disable-reason counts list no person."""
    # Assert
    assert "Needs a look" in tour["device"] and "hidden" in tour["device"] and "SN-INVENTED" not in tour["device"] and "222222" not in tour["device"]
    assert "VPN conflict" in tour["disable"] and "@" not in tour["disable"] and "jordan" not in tour["disable"]


def test_every_new_control_is_keyboard_reachable(tour):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3: every new control on both pages takes keyboard focus."""
    # Assert
    assert all(tour["focus"]) and all(tour["fleetFocus"]), (tour["focus"], tour["fleetFocus"])


def test_no_sideways_scroll_at_320px_with_the_new_sections_open(tour):
    """WCAG 2.2 SC 1.4.10 (Reflow): at 320px, with the ZDX panel open and the results drawn, neither page scrolls sideways."""
    # Assert
    assert tour["narrowPath"] <= 0 and tour["narrowFleet"] <= 0, (tour["narrowPath"], tour["narrowFleet"])


def test_the_panel_words_keep_aa_contrast_and_the_tour_has_no_errors(tour):
    """WCAG 2.2 SC 1.4.3 · ASVS V14.1 · CWE-755: every word of the ZDX panel keeps at least 4.5:1, and the tour left no script error or failed request."""
    # Assert
    assert tour["contrast"] and min(tour["contrast"]) >= 4.5, tour["contrast"]
    assert tour["errors"] == [], tour["errors"]
