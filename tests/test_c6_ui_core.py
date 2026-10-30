"""Cloud QA wave 6, UI core: the main page, Simple mode, the guide and the
report pages, driven in a real browser (Playwright, headless Chromium) on
the sample tenant, and a hostile copy of it whose every name is markup.

What the browser part proves, each scenario once per module run:
  - tenant strings never become markup on any page (hostile sample tenant);
  - the partial-scan card ("N checks could not run") shows after a run: a
    second renderPermissions() in index.html had silently replaced it;
  - results restored from sessionStorage, custom channels and the last
    deployment from localStorage, and a stored deployment record are read
    as data: numbers are numbers, an icon is the fixed one, text is escaped;
  - Save config says so when the browser blocks storage, and Clear config
    still clears the fields;
  - the SSO sign-in link only ever points at a path on this origin;
  - a browser that refuses alert/confirm/prompt never kills the button
    that asked: the app's dialog shows the text and the answer is "no";
  - no secret typed into the form reaches localStorage or sessionStorage;
  - every page has accessible names, unique ids, text contrast of at least
    4.5:1 (3:1 for large text) in the light and the dark theme, and no
    sideways scroll at 320px.

Skips when node or Playwright is missing. No network: the app runs on an
ephemeral loopback port with its own temporary stores, and the browser
refuses every request that is not to it.
"""
import collections
import json
import os
import re
import shutil
import subprocess
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD = '<img src=x onerror="(window.__xss=window.__xss||[]).push(1)">'
CANARY = "CANARY-c6-ui-core-secret-7f3a"
MY_PAGES = ["/", "/simple", "/report/todo", "/report/view", "/report/compliance", "/report/digest",
            "/report/health", "/report/audit", "/report/exports", "/report/evalall", "/report/posture",
            "/report/self-heal", "/report/queue", "/report/beacon", "/report/vendor", "/report/logs"]


def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def _playwright_ok(node):
    try:
        r = subprocess.run([node, "-e", "require('playwright')"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _hostile(value, key=None):
    """The sample tenant with every display string (names, descriptions) ending in markup."""
    if isinstance(value, dict):
        return {k: _hostile(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_hostile(v, key) for v in value]
    if isinstance(value, str) and key in {"name", "description", "displayName", "orgName", "loginName", "desc", "label", "title", "comment", "notes"}:
        return value + PAYLOAD
    return value


DRIVER = r"""
const { chromium } = require('playwright');
const [base, chrome, pagesJson, payload, canary] = process.argv.slice(2);
const PAGES = JSON.parse(pagesJson);
const out = {};
const metric = () => {
  // Contrast (WCAG 1.4.3), accessible names (4.1.2), unique ids (4.1.1) and reflow (1.4.10) on what is shown.
  const W = document.documentElement.clientWidth;
  const lum = c => { const srgb = /^color\(srgb/.test(c); const m = c.replace(/^color\(srgb/, '').match(/[\d.]+/g); if (!m) return null;
    const [r, g, b] = m.slice(0, 3).map(x => { x = srgb ? +x : x / 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
    return { L: 0.2126 * r + 0.7152 * g + 0.0722 * b, a: m.length > 3 ? +m[3] : 1 }; };
  const bgOf = el => { for (let e = el; e; e = e.parentElement) { const s = getComputedStyle(e); if (s.backgroundImage && s.backgroundImage !== 'none' && !/gradient/.test(s.backgroundImage)) return null; const l = lum(s.backgroundColor); if (l && l.a >= 0.9) return l.L; } return null; };
  const hidden = el => { for (let e = el; e; e = e.parentElement) { const s = getComputedStyle(e); if (e.hidden || s.display === 'none' || s.visibility === 'hidden' || +s.opacity < 0.5) return true; } return false; };
  const low = [], seen = new Set();
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    const el = w.currentNode.parentElement; if (!el || seen.has(el) || !w.currentNode.textContent.trim()) continue; seen.add(el);
    const r = el.getBoundingClientRect(); if (!r.width || !r.height || hidden(el) || el.closest('[aria-hidden="true"],.sr-only,button:disabled,[disabled]')) continue;
    const s = getComputedStyle(el), fg = lum(s.color), bg = bgOf(el); if (!fg || fg.a < 0.5 || bg == null) continue;
    const ratio = (Math.max(fg.L, bg) + 0.05) / (Math.min(fg.L, bg) + 0.05);
    const big = parseFloat(s.fontSize) >= 24 || (parseFloat(s.fontSize) >= 18.66 && +s.fontWeight >= 700);
    if (ratio < (big ? 3 : 4.5) - 0.01) low.push(`${el.tagName}.${String(el.className).slice(0, 30)} ${ratio.toFixed(2)} "${w.currentNode.textContent.trim().slice(0, 30)}"`);
  }
  const nameless = [...document.querySelectorAll('button, a[href], input:not([type=hidden]), select, textarea, [role=button]')].filter(e => {
    if (!e.getBoundingClientRect().width || hidden(e)) return false;
    const lb = (e.getAttribute('aria-labelledby') || '').split(/\s+/).map(i => (document.getElementById(i) || {}).textContent || '').join('');
    const n = (e.getAttribute('aria-label') || lb || e.textContent || e.title || (e.type !== 'text' && e.value) || e.placeholder || '').trim();
    return !n && !(e.id && document.querySelector(`label[for="${CSS.escape(e.id)}"]`)) && !e.closest('label');
  }).map(e => e.tagName + '#' + e.id + '.' + String(e.className).slice(0, 30));
  const ids = {}; document.querySelectorAll('[id]').forEach(e => { ids[e.id] = (ids[e.id] || 0) + 1; });
  return { low: low.slice(0, 10), nameless: nameless.slice(0, 10), dupIds: Object.keys(ids).filter(k => ids[k] > 1),
           overflow: document.documentElement.scrollWidth - W, h1: [...document.querySelectorAll('h1')].filter(h => !hidden(h)).length };
};
const xssCount = () => [(window.__xss || []).length, document.querySelectorAll('img[src="x"]').length];
// A scenario that throws records its error under its key; the others still run.
async function grab(key, promise) { try { out[key] = await promise; } catch (e) { out[key] = { __error: String(e && e.message || e).slice(0, 300) }; } return out[key]; }
(async () => {
  const b = await chromium.launch(chrome ? { executablePath: chrome } : {});
  async function context(opts, init) {
    const ctx = await b.newContext(Object.assign({ viewport: { width: 1280, height: 900 } }, opts || {}));
    await ctx.route(u => !u.toString().startsWith(base) && !/^(data|blob|about):/.test(u.toString()), r => r.abort());
    if (init) await ctx.addInitScript(init);
    const errs = [], dialogs = [];
    ctx.on('page', p => { p.on('pageerror', e => errs.push(p.url().replace(base, '') + ' ' + e.message)); p.on('dialog', d => { dialogs.push(d.type()); d.dismiss().catch(() => {}); }); });
    const p0 = await ctx.newPage(); await p0.goto(base + '/api/health'); await p0.request.post(base + '/api/offline/sample', { data: {} }); await p0.close();
    return { ctx, errs, dialogs };
  }
  async function open(ctx, path) { const pg = await ctx.newPage(); await pg.goto(base + path, { waitUntil: 'networkidle' }); return pg; }
  async function assess(pg) {
    await pg.evaluate(() => { document.getElementById('org').value = 'Larkspur'; document.getElementById('assessor').value = 'QA'; runAssessment(); });
    await pg.waitForFunction(() => /complete/i.test(document.getElementById('statusMsg').textContent), null, { timeout: 120000 });
    await pg.waitForLoadState('networkidle');
  }

  // 1. Hostile tenant names on every page, before and after an assessment.
  {
    const { ctx, errs } = await context();
    out.hostile = {};
    for (const path of PAGES) { const pg = await open(ctx, path); out.hostile[path] = await pg.evaluate(xssCount); await pg.close(); }
    const main = await open(ctx, '/');
    await assess(main);
    out.hostile['/ after run'] = await main.evaluate(xssCount);
    await grab('checksRun', main.evaluate(() => reportData && reportData.checks.length));
    for (const path of ['/report/todo', '/report/view?tool=results', '/report/compliance', '/simple']) { const pg = await open(ctx, path); out.hostile[path + ' after run'] = await pg.evaluate(xssCount); await pg.close(); }
    out.hostileErrors = errs.slice();

    // 2. The partial-scan card after a run in which the role blocked checks.
    await grab('partial', main.evaluate(() => {
      const d = Object.assign({}, reportData, { permissions: { blocked: 2, note: 'Grant the role.', checks: [{ id: 'FW.1', label: 'Firewall', section: 'ZIA' }, { id: 'FW.2', label: 'IPS', section: 'ZIA' }],
        needed_for_full_scan: [{ scope: 'zia_extras', label: 'Cloud Firewall', service: 'ZIA', blocked_checks: 2, permissions: ['Firewall'] }] } });
      showResults(d);
      const card = document.getElementById('permissionsCard');
      return { shown: getComputedStyle(card).display !== 'none', text: document.getElementById('permissionsBody').textContent.replace(/\s+/g, ' ').trim().slice(0, 200),
               modalUntouched: !/could not run/.test((document.getElementById('permissionsContent') || {}).textContent || '') };
    }));
    // 3. Results restored from this tab's sessionStorage are data: hostile "numbers" are not drawn.
    await grab('restored', main.evaluate(async payload => {
      const d = JSON.parse(sessionStorage.getItem('zassess_last_results'));
      const k = Object.keys(d.sections)[0];
      Object.assign(d.sections[k], { pct: payload, pass: payload, total: payload, scored: payload });
      d.score = payload; d.permissions = { blocked: payload };
      sessionStorage.setItem('zassess_last_results', JSON.stringify(d));
      return k;
    }, payload));
    await main.reload({ waitUntil: 'networkidle' });
    await grab('restoredAfter', main.evaluate(k => ({ x: [(window.__xss || []).length, document.querySelectorAll('img[src="x"]').length], restored: !!(reportData && reportData.__restored),
      sec: reportData && reportData.sections[k] && reportData.sections[k].pct }), out.restored));
    // 4. The last deployment and custom channels from localStorage are data too.
    await grab('guide', main.evaluate(payload => {
      localStorage.setItem('zassess_last_deploy', JSON.stringify({ at: 'today', status: 'ok', created: payload }));
      return _gdSteps().map(s => s.status).join(' ');
    }, payload));
    await grab('deployments', main.evaluate(payload => {
      DZ.deployments = [{ id: 'dep-1', at: '2026-10-01T00:00:00Z', tenant_label: 'Sample', packs: ['p1'], created: 2, remaining: 2, created_by_kind: { rule: 2 },
        channel_targets: { p1: ['web', payload], p2: 'not-a-list' } }];
      const host = document.createElement('div'); host.innerHTML = _dzDeploymentsHtml();
      return { imgs: host.querySelectorAll('img').length, text: host.textContent.replace(/\s+/g, ' ') };
    }, payload));
    await main.evaluate(payload => {
      localStorage.setItem('zassess_channels_v1_extra', JSON.stringify([{ id: 'custom_1', name: 'Kept channel', icon: payload, what: payload },
        { id: '<b>bad</b>', name: 'Dropped id' }, { id: 'custom_2' }, 'junk', null]));
    }, payload);
    await main.reload({ waitUntil: 'networkidle' });
    await grab('channels', main.evaluate(() => { window.__dbShowScope && window.__dbShowScope(); const rows = [...document.querySelectorAll('#dbScopeView .db-ch-row')];
      return { names: rows.map(r => (r.querySelector('strong') || {}).textContent), imgs: document.querySelectorAll('#dbScopeView img').length, x: (window.__xss || []).length }; }));
    await main.evaluate(() => localStorage.setItem('zassess_channels_v1_extra', '{"not":"a list"}'));
    await main.reload({ waitUntil: 'networkidle' });
    await grab('channelsObject', main.evaluate(() => { window.__dbShowScope && window.__dbShowScope(); return document.querySelectorAll('#dbScopeView .db-ch-row').length; }));
    out.storedErrors = errs.slice(out.hostileErrors.length);
    await ctx.close();
  }

  // 5. Save config and Clear config with the browser's storage blocked.
  {
    const { ctx, errs } = await context({}, () => { Object.defineProperty(window, 'localStorage', { configurable: true, get() { throw new DOMException('blocked', 'SecurityError'); } }); });
    const pg = await open(ctx, '/');
    await grab('blocked', pg.evaluate(() => {
      const r = {};
      document.getElementById('org').value = 'Larkspur';
      try { saveConfig(); r.save = 'ok'; } catch (e) { r.save = 'threw ' + e.name; }
      r.status = document.getElementById('statusMsg').textContent;
      r.cls = document.getElementById('statusMsg').className;
      try { clearConfig(); r.clear = 'ok'; } catch (e) { r.clear = 'threw ' + e.name; }
      r.orgAfterClear = document.getElementById('org').value;
      return r;
    }));
    out.blockedErrors = errs.slice();
    await ctx.close();
  }

  // 6. The SSO bar: the sign-in link is a path on this origin, whatever the server says.
  {
    out.sso = {};
    for (const url of ['javascript:alert(1)', '//evil.example/x', '/\\evil.example', 'https://evil.example/login', ' /api/auth/sso/login', '/api/auth/sso/login?next=%2F']) {
      const { ctx } = await context();
      await ctx.route(base + '/api/auth/status', r => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ sso: true, unlocked: false, required: true, sso_login_url: url }) }));
      const pg = await open(ctx, '/report/todo');
      await pg.waitForSelector('#dlpSsoBar a');
      out.sso[url] = await pg.evaluate(() => document.querySelector('#dlpSsoBar a').getAttribute('href'));
      await ctx.close();
    }
  }

  // 7. A browser that refuses alert / confirm / prompt (an embedded browser throws "not supported").
  {
    const { ctx, errs, dialogs } = await context({}, () => {
      for (const n of ['alert', 'confirm', 'prompt']) window[n] = function () { throw new Error(n + '() is not supported.'); };
    });
    const pg = await open(ctx, '/report/todo');
    await grab('refused', pg.evaluate(() => {
      const r = { confirm: confirm('Delete everything?'), prompt: prompt('Name?', 'x') };
      r.alert = alert('Line one\nLine two') === undefined;
      const d = [...document.querySelectorAll('dialog.dlp-dlg')];
      r.dialogs = d.length; r.text = d.map(x => x.textContent.replace(/\s+/g, ' ').trim()).join(' | ').slice(0, 600);
      return r;
    }));
    const main = await open(ctx, '/');
    await main.evaluate(() => window.__dbShowScope());
    try { await main.click('#dbChAdd'); await main.waitForSelector('dialog.dlp-dlg[open]', { timeout: 5000 }); } catch (e) { /* recorded below: no dialog */ }
    await grab('refusedAdd', main.evaluate(() => ({ dialog: document.querySelector('dialog.dlp-dlg[open]').textContent.replace(/\s+/g, ' ').slice(0, 300), rows: document.querySelectorAll('#dbScopeView .db-ch-row').length })));
    out.refusedErrors = errs.slice(); out.refusedNative = dialogs.slice();
    await ctx.close();
  }

  // 8. Nothing secret reaches web storage: a canary secret typed and saved, an assessment run.
  {
    const { ctx } = await context();
    const pg = await open(ctx, '/');
    await pg.evaluate(c => { for (const id of ['csec', 'zpass', 'zkey']) { const e = document.getElementById(id); if (e) e.value = c; } document.getElementById('vd').value = 'larkspur'; document.getElementById('cid').value = 'client-id-1'; saveConfig(); }, canary);
    await assess(pg);
    await grab('storage', pg.evaluate(() => { const all = {}; for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) { const k = s.key(i); all[k] = s.getItem(k); } return all; }));
    await ctx.close();
  }

  // 10. Keyboard: each modal of the main page keeps Tab and Shift+Tab inside it, Escape closes it, focus goes back.
  {
    const { ctx, errs } = await context();
    const pg = await open(ctx, '/');
    out.trap = {};
    for (const fn of ['openBestPracticesModal', 'openUpdateModal', 'openDlpEfficacyModal', 'openPermissionsModal', 'openBypassModal', 'openDlpPacksModal', 'openTerraformModal']) {
      const r = out.trap[fn] = { left: [] };
      try {
        await pg.evaluate(fn => { const b = document.createElement('button'); b.id = 'c6Opener'; b.textContent = 'Opener'; document.body.appendChild(b); b.focus(); window[fn](); }, fn);
        await pg.waitForFunction(() => [...document.querySelectorAll('[role="dialog"][aria-modal="true"]')].some(m => m.getClientRects().length && getComputedStyle(m).display !== 'none' && m.contains(document.activeElement)));
        r.modal = await pg.evaluate(() => document.activeElement.closest('[role="dialog"]').id);
        for (const key of ['Tab', 'Shift+Tab']) for (let i = 0; i < 40; i++) {
          await pg.keyboard.press(key);
          const where = await pg.evaluate(id => document.getElementById(id).contains(document.activeElement) ? null : (document.activeElement.tagName + '#' + document.activeElement.id), r.modal);
          if (where && !r.left.includes(where)) r.left.push(where);
        }
        // A help pop-up (static/hover_help.js) takes the first Escape (WCAG 1.4.13: dismissed
        // without moving focus) and must leave the dialog open and focus where it was; the next
        // Escape is the dialog's. Opened here from the modal's first "?" mark, with Enter.
        const state = () => pg.evaluate(id => { const t = document.getElementById('hhTip'), m = document.getElementById(id);
          return { tip: !!(t && !t.hidden), modalOpen: !!(m.getClientRects().length && getComputedStyle(m).display !== 'none'), focusKept: document.activeElement === window.__c6Focus }; }, r.modal);
        r.tipAfterTab = (await state()).tip;
        r.mark = await pg.evaluate(id => { const k = [...document.getElementById(id).querySelectorAll('.hh-mark')].find(b => b.getClientRects().length && !b.hidden);
          if (k) k.focus(); return !!k && document.activeElement === k; }, r.modal);
        if (r.mark) await pg.keyboard.press('Enter');
        await pg.evaluate(() => { window.__c6Focus = document.activeElement; });
        r.tip = (await state()).tip;
        if (r.tip) { await pg.keyboard.press('Escape'); r.tipEscape = await state(); }
        await pg.keyboard.press('Escape');
        await pg.waitForFunction(id => { const m = document.getElementById(id); return !m.getClientRects().length || getComputedStyle(m).display === 'none'; }, r.modal, { timeout: 15000 });
        r.back = await pg.evaluate(() => document.activeElement && document.activeElement.id);
      } catch (e) { r.__error = String(e && e.message || e).slice(0, 200); }
      // Isolation: whatever this one left open is closed before the next.
      await pg.evaluate(() => {
        for (const f of ['closeBestPracticesModal', 'closeUpdateModal', 'closeDlpEfficacyModal', 'closePermissionsModal', 'closeBypassModal', 'closeDlpPacksModal', 'closeTerraformModal']) { try { if (typeof window[f] === 'function') window[f](); } catch (e) { /* not open */ } }
        const b = document.getElementById('c6Opener'); if (b) b.remove();
      });
    }
    // The Terraform dialog redraws its body when its packs load, a pack is ticked or the mode
    // changes: focus stays on the same control, never falls out of the dialog to <body>.
    await grab('tfRedraw', (async () => {
      const r = {};
      await pg.evaluate(() => openTerraformModal());
      await pg.waitForFunction(() => document.querySelector('#terraformBody .tf-pack input') && !/loading/i.test(document.getElementById('terraformBody').textContent), null, { timeout: 30000 });
      const where = () => pg.evaluate(() => { const a = document.activeElement; return { inDialog: document.getElementById('terraformModal').contains(a), tag: a.tagName, change: a.getAttribute('onchange'), checked: !!a.checked }; });
      const box = await pg.evaluate(() => document.querySelector('#terraformBody .tf-pack input').getAttribute('onchange'));
      await pg.focus('#terraformBody .tf-pack input');
      await pg.keyboard.press('Space');   // ticks the pack: a summary loads, the body redraws
      await pg.waitForFunction(() => !/loading/i.test(document.getElementById('terraformBody').textContent), null, { timeout: 30000 });
      r.tick = Object.assign(await where(), { same: (await where()).change === box });
      await pg.focus('#terraformBody summary');
      await pg.evaluate(() => _tfRender());
      r.redraw = await where();
      await pg.evaluate(() => closeTerraformModal());
      return r;
    })());
    out.trapErrors = errs.slice();
    await ctx.close();
  }

  // 9. Contrast, names, ids and reflow on every page, both themes, desktop and 320px.
  out.a11y = {};
  for (const scheme of ['dark', 'light']) for (const width of [1280, 320]) {
    const { ctx } = await context({ colorScheme: scheme, viewport: { width, height: 900 } });
    for (const path of PAGES) { const pg = await open(ctx, path); out.a11y[`${scheme} ${width} ${path}`] = await pg.evaluate(metric); await pg.close(); }
    await ctx.close();
  }
  console.log(JSON.stringify(out));
  await b.close();
})().catch(e => { console.error(e && e.stack || e); process.exit(1); });
"""


def _serve_and_drive(tmp_dir, driver, args, env, patches=()):
    """Serve the real app on an ephemeral loopback port with `env` and
    `patches` (obj, name, value), run the Playwright `driver` against it and
    return its JSON. Isolated: temporary stores and token folder."""
    node = shutil.which("node")
    if not node or not _playwright_ok(node):
        pytest.skip("needs node and Playwright")
    import uvicorn
    import dlp_api_server as srv
    mp = pytest.MonkeyPatch()
    for key, name in (("DLP_CHECK_PROFILES", "profiles.json"), ("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_UI_TOKEN_DIR", ""), ("DLP_CHECK_ZIA_RATE_STATE", "rate.json")):
        mp.setenv(key, str(tmp_dir / name) if name else str(tmp_dir))
    (tmp_dir / "profiles.json").write_text("{}")
    mp.setenv("ENABLE_WRITE_ACTIONS", "")
    for k, v in env.items():
        mp.setenv(k, v)
    mp.setattr(srv, "_latest_remote_commit", lambda branch="main": None)
    for obj, name, value in patches:
        mp.setattr(obj, name, value)
    server = uvicorn.Server(uvicorn.Config(srv.app, host="127.0.0.1", port=0, lifespan="off", log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not (server.started and server.servers) and time.monotonic() < deadline:
            time.sleep(0.02)   # bounded wait for the socket, not a fixed delay
        assert server.started, "the app did not start"
        port = server.servers[0].sockets[0].getsockname()[1]
        (tmp_dir / "drive.js").write_text(driver, encoding="utf-8")
        chrome = os.environ.get("CHROME_BIN", "")
        r = subprocess.run([node, str(tmp_dir / "drive.js"), f"http://127.0.0.1:{port}", chrome if chrome and os.path.exists(chrome) else "", *args],
                           capture_output=True, text=True, timeout=900, cwd=str(tmp_dir))
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        mp.undo()
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def ui(tmp_path_factory):
    """The app on the hostile sample tenant, driven once by DRIVER; its JSON."""
    import offline_tenant
    import sample_tenant
    real = sample_tenant.responses
    try:
        # The hostile copy is built when the sample is first opened (by the driver).
        offline_tenant._OPEN.pop(offline_tenant.SAMPLE, None)
        return _serve_and_drive(tmp_path_factory.mktemp("c6-ui-core"), DRIVER, [json.dumps(MY_PAGES), PAYLOAD, CANARY],
                                {"ZSCALER_UI_AUTH": "0"}, [(sample_tenant, "responses", lambda: _hostile(real()))])
    finally:
        offline_tenant._OPEN.pop(offline_tenant.SAMPLE, None)


TOKEN = "tok-c6-ui-core-0123456789abcdef"
LOCKED_DRIVER = r"""
const { chromium } = require('playwright');
const [base, chrome, token] = process.argv.slice(2);
const out = {};
(async () => {
  const b = await chromium.launch(chrome ? { executablePath: chrome } : {});
  for (const path of ['/report/todo', '/']) {
    const ctx = await b.newContext();
    await ctx.route(u => !u.toString().startsWith(base), r => r.abort());
    const pg = await ctx.newPage(); const r = { native: [], errs: [] };
    out[path] = r;
    pg.on('dialog', d => { r.native.push(d.type()); d.dismiss().catch(() => {}); }); pg.on('pageerror', e => r.errs.push(e.message));
    try {
    await pg.goto(base + path);
    const ask = () => pg.waitForSelector('dialog.dlp-dlg[open] #dlpUnlockToken', { timeout: 10000 });
    await ask();
    r.field = await pg.evaluate(() => { const i = document.getElementById('dlpUnlockToken'); return { type: i.type, ac: i.autocomplete, focused: document.activeElement === i }; });
    await pg.fill('dialog.dlp-dlg[open] #dlpUnlockToken', 'not-the-token'); await pg.click('dialog.dlp-dlg[open] #dlpUnlockGo');
    await ask();
    r.again = await pg.evaluate(() => document.querySelector('dialog.dlp-dlg[open]').textContent.replace(/\s+/g, ' '));
    await pg.fill('dialog.dlp-dlg[open] #dlpUnlockToken', token); await pg.click('dialog.dlp-dlg[open] #dlpUnlockGo');
    await pg.waitForFunction(() => !document.querySelector('dialog.dlp-dlg'));
    r.health = await pg.evaluate(async () => (await fetch('/api/health')).status);
    r.tokenInPage = await pg.evaluate(t => document.documentElement.outerHTML.includes(t) || [...document.querySelectorAll('input')].some(i => (i.value || '').includes(t)) || location.href.includes(t) || document.cookie.includes(t), token);
    r.tokenInStorage = await pg.evaluate(t => { for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) if ((s.getItem(s.key(i)) || '').includes(t)) return true; return false; }, token);
    r.cookies = (await ctx.cookies()).filter(c => c.value === token).map(c => ({ httpOnly: c.httpOnly, sameSite: c.sameSite }));
    } catch (e) { r.__error = String(e && e.message || e).slice(0, 300); }
    await ctx.close();
  }
  // Three refused tokens, then quiet: the page does not keep asking.
  {
    const ctx = await b.newContext(); await ctx.route(u => !u.toString().startsWith(base), r => r.abort());
    const pg = await ctx.newPage(); let asked = 0;
    out.capped = {};
    try {
    await pg.goto(base + '/report/todo');
    for (let i = 0; i < 3; i++) { await pg.waitForSelector('dialog.dlp-dlg[open] #dlpUnlockToken', { timeout: 10000 }); asked++; await pg.fill('dialog.dlp-dlg[open] #dlpUnlockToken', 'wrong-' + i); await pg.click('dialog.dlp-dlg[open] #dlpUnlockGo'); await pg.waitForFunction(n => document.querySelectorAll('dialog.dlp-dlg').length === 0 || !document.querySelector('dialog.dlp-dlg[open] #dlpUnlockToken') || document.getElementById('dlpUnlockToken').value === '', null, { timeout: 5000 }); }
    out.capped = { asked, status: await pg.evaluate(async () => (await fetch('/api/health')).status), openAfter: await pg.evaluate(() => document.querySelectorAll('dialog.dlp-dlg[open]').length) };
    } catch (e) { out.capped = { asked, __error: String(e && e.message || e).slice(0, 300) }; }
    await ctx.close();
  }
  console.log(JSON.stringify(out));
  await b.close();
})().catch(e => { console.error(e && e.stack || e); process.exit(1); });
"""


@pytest.fixture(scope="module")
def locked(tmp_path_factory):
    """The app with its UI token gate on and a known token, driven by LOCKED_DRIVER."""
    import security
    return _serve_and_drive(tmp_path_factory.mktemp("c6-ui-locked"), LOCKED_DRIVER, [TOKEN], {"ZSCALER_UI_AUTH": "1"},
                            [(security, "_ui_token", TOKEN)])


# ── Injection (CWE-79) ──────────────────────────────────────────────

def test_hostile_tenant_names_never_become_markup_on_any_page(ui):
    """ASVS V5.3.3 · A03:2021 · CWE-79 · WSTG-CLNT-01: every name of a hostile sample tenant is shown as text on each page, before and after a run."""
    assert ui["checksRun"] > 100, "the assessment really ran on the hostile tenant"
    assert {k: v for k, v in ui["hostile"].items() if v != [0, 0]} == {}
    assert ui["hostileErrors"] == []


def test_restored_results_are_numbers_not_markup(ui):
    """ASVS V5.3.3 · V5.1.4 · CWE-79 · CWE-20 · WSTG-CLNT-01: results read back from sessionStorage are coerced to numbers before the tiles draw them."""
    r = ui["restoredAfter"]
    assert r["restored"] is True
    assert r["x"] == [0, 0]
    assert r["sec"] is None, "a non-numeric percentage reads as not measured"


def test_the_last_deployment_from_storage_is_counted_not_parsed(ui):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the guide's 'Last deployment' line prints a number, never stored markup."""
    assert "<img" not in ui["guide"]
    assert "0 created." in ui["guide"]


def test_a_stored_deployment_record_shows_unknown_channels_as_text(ui):
    """ASVS V5.3.3 · A03:2021 · CWE-79 · WSTG-INPV-02: an unknown channel name in a deployment record is escaped in Previous deployments."""
    d = ui["deployments"]
    assert d["imgs"] == 0
    assert "Inline Web DLP, <img src=x" in d["text"], "the known channel keeps its label; the unknown one is shown as text"
    assert "p2: as packed" in d["text"], "a malformed channel list is ignored, not iterated as characters"


def test_custom_channels_from_storage_are_rebuilt_from_their_name(ui):
    """ASVS V5.1.4 · V5.3.3 · CWE-79 · CWE-20: only {id: custom_*, name} survives; the icon and text are the app's own."""
    c = ui["channels"]
    assert c["imgs"] == 0 and c["x"] == 0
    assert "Kept channel" in c["names"]
    assert "Dropped id" not in c["names"], "an id that is not custom_* is dropped"
    assert ui["channelsObject"] >= 10, "a stored object instead of a list falls back to the built-in channels"


def test_malformed_stored_state_never_breaks_the_page(ui):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-ERRH-01: null, a string or an object where a list of channels was stored raises no error on the page."""
    assert ui["storedErrors"] == []


# ── Function: the partial-scan card ─────────────────────────────────

def test_the_partial_scan_card_shows_after_a_run_with_blocked_checks(ui):
    """ASVS V7.4.1 · CWE-1041 · WCAG 2.2 SC 3.3.1: after a run the role partly blocked, the card says how many checks could not run and what to grant."""
    p = ui["partial"]
    assert p["shown"] is True
    assert "2 checks could not run" in p["text"] and "Cloud Firewall" in p["text"]
    assert p["modalUntouched"] is True, "the Required API access dialog is not overwritten with the run's data"


def test_no_two_scripts_of_the_main_page_declare_the_same_global_function():
    """ASVS V1.14.1 · CWE-1041 · NIST SSDF PW.7: a top-level function declared twice silently replaces the first (renderPermissions did)."""
    # Arrange
    import dlp_api_server as srv
    html = _read("static", "index.html")
    sources = {"index.html": "\n".join(re.findall(r"<script(?![^>]*src)[^>]*>(.*?)</script>", html, re.S))}
    for name in [n for n, k in srv.GUI_ADDONS if k == "script"] + re.findall(r'<script src="/static/([^"]+)"', html):
        sources[name] = _read("static", name)
    # Act
    seen = collections.defaultdict(list)
    for name, text in sources.items():
        for m in re.finditer(r"^(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)", text, re.M):
            seen[m.group(1)].append(name)
    # Assert
    assert {k: v for k, v in seen.items() if len(v) > 1} == {}


def test_the_duplicate_check_would_catch_a_redeclaration():
    """ASVS V1.14.1 · CWE-1041: the scan above finds a function declared twice (negative control)."""
    text = "function a() {}\nasync function b() {}\nfunction a() {}\n"
    names = [m.group(1) for m in re.finditer(r"^(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)", text, re.M)]
    assert collections.Counter(names)["a"] == 2


# ── Storage (CWE-922, CWE-755) ──────────────────────────────────────

def test_save_config_says_so_when_storage_is_blocked(ui):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: with site storage blocked, Save config reports it plainly instead of throwing."""
    b = ui["blocked"]
    assert b["save"] == "ok", b
    assert "not saved" in b["status"] and "error" in b["cls"]
    assert ui["blockedErrors"] == []


def test_clear_config_still_clears_the_fields_when_storage_is_blocked(ui):
    """ASVS V7.4.1 · CWE-755: Clear config empties the form even when it cannot reach storage."""
    assert ui["blocked"]["clear"] == "ok"
    assert ui["blocked"]["orgAfterClear"] == ""


def test_no_secret_typed_into_the_form_reaches_web_storage(ui):
    """ASVS V8.2.2 · V8.3.4 · A04:2021 · CWE-922 · CWE-312: a canary secret typed, saved and run with is in no localStorage or sessionStorage value."""
    store = ui["storage"]
    assert "zscaler_made_easy_config" in store, "Save config ran"
    assert "zassess_last_results" in store, "the run's results were kept for this tab"
    assert [k for k, v in store.items() if CANARY in (v or "")] == []
    assert json.loads(store["zscaler_made_easy_config"]).get("cid") == "client-id-1", "the non-secret client id is kept"


@pytest.mark.parametrize("name", ["index.html", "guide.js", "dashboard.js", "deploy_studio.js", "report_exports.html", "sidebar_order.js", "report_theme.js", "simple.js"])
def test_every_web_storage_call_is_guarded(name):
    """ASVS V7.4.1 · CWE-755: a localStorage/sessionStorage call sits in a try block (storage may throw), per file."""
    text = _read("static", name)
    bad = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\b(localStorage|sessionStorage)\.(getItem|setItem|removeItem)\(", line) and not line.lstrip().startswith("//"):
            window = "\n".join(lines[max(0, i - 8):i + 1])
            if "try" not in window:
                bad.append(f"{name}:{i + 1}: {line.strip()[:100]}")
    assert bad == []


# ── Navigation targets (CWE-601) ────────────────────────────────────

@pytest.mark.parametrize("given,expected", [
    ("javascript:alert(1)", "/api/auth/sso/login"),
    ("//evil.example/x", "/api/auth/sso/login"),
    ("/\\evil.example", "/api/auth/sso/login"),
    ("https://evil.example/login", "/api/auth/sso/login"),
    (" /api/auth/sso/login", "/api/auth/sso/login"),
    ("/api/auth/sso/login?next=%2F", "/api/auth/sso/login?next=%2F"),
])
def test_the_sso_sign_in_link_is_only_ever_a_path_on_this_origin(ui, given, expected):
    """ASVS V5.1.5 · A01:2021 · CWE-601 · WSTG-CLNT-04: a sign-in address that is not a same-origin path falls back to the fixed one (boundary: a real path with a query is kept)."""
    assert ui["sso"][given] == expected


# ── Refused browser dialogs (CWE-755) ───────────────────────────────

def test_a_refused_confirm_or_prompt_reads_as_no_and_never_throws(ui):
    """ASVS V7.4.1 · V11.1.1 · CWE-755 · CWE-841 · WSTG-ERRH-01: when the browser refuses its own boxes, confirm() is false and prompt() is null (fail closed)."""
    r = ui["refused"]
    assert r["confirm"] is False and r["prompt"] is None and r["alert"] is True
    assert ui["refusedErrors"] == []


def test_a_refused_box_shows_its_text_in_the_apps_dialog(ui):
    """ASVS V7.4.1 · CWE-755 · WCAG 2.2 SC 3.3.1: the question or message is shown in the app's own dialog, with what to do."""
    r = ui["refused"]
    assert r["dialogs"] >= 1
    assert "Line one" in r["text"] and "Delete everything?" in r["text"] and "Chrome or Edge" in r["text"]


def test_add_channel_survives_a_browser_that_refuses_prompt(ui):
    """ASVS V7.4.1 · CWE-755: the Add channel button no longer dies on a refused prompt(): it says why and adds nothing."""
    a = ui["refusedAdd"]
    assert "could not ask" in a["dialog"] and "Name the channel" in a["dialog"]
    assert ui["refusedNative"] == [], "the stubbed boxes threw; no native dialog opened"


# ── Accessibility: contrast, names, ids, reflow (WCAG 2.2 AA) ───────

def _a11y(ui, key):
    return ui["a11y"][key]


@pytest.mark.parametrize("scheme", ["dark", "light"])
@pytest.mark.parametrize("path", MY_PAGES)
def test_text_contrast_meets_aa_in_both_themes(ui, scheme, path):
    """WCAG 2.2 SC 1.4.3 · SC 1.4.6 (AA part only): shown text is at least 4.5:1 (3:1 large) on its background, light and dark."""
    assert _a11y(ui, f"{scheme} 1280 {path}")["low"] == []
    assert _a11y(ui, f"{scheme} 320 {path}")["low"] == []


@pytest.mark.parametrize("path", MY_PAGES)
def test_every_control_has_an_accessible_name_and_ids_are_unique(ui, path):
    """WCAG 2.2 SC 4.1.2 · SC 1.3.1: every shown control has a name and no id is used twice."""
    for scheme in ("dark", "light"):
        m = _a11y(ui, f"{scheme} 1280 {path}")
        assert m["nameless"] == [] and m["dupIds"] == [], (scheme, m)


@pytest.mark.parametrize("path", MY_PAGES)
def test_no_page_scrolls_sideways_at_320px_in_either_theme(ui, path):
    """WCAG 2.2 SC 1.4.10: no horizontal scroll at 320 CSS px (boundary), dark and light."""
    for scheme in ("dark", "light"):
        assert _a11y(ui, f"{scheme} 320 {path}")["overflow"] == 0, scheme


@pytest.mark.parametrize("path", MY_PAGES)
def test_each_page_shows_exactly_one_main_heading(ui, path):
    """WCAG 2.2 SC 1.3.1 · SC 2.4.6: one visible h1 per page."""
    assert _a11y(ui, f"dark 1280 {path}")["h1"] == 1


# ── Keyboard (WCAG 2.1.2, 2.4.3) ────────────────────────────────────

MODALS = ["openBestPracticesModal", "openUpdateModal", "openDlpEfficacyModal", "openPermissionsModal", "openBypassModal", "openDlpPacksModal", "openTerraformModal"]


@pytest.mark.parametrize("fn", MODALS)
def test_tab_never_leaves_an_open_modal(ui, fn):
    """WCAG 2.2 SC 2.4.3 · SC 2.1.2 · ASVS V1.1 (n/a): forty Tab and forty Shift+Tab presses keep focus inside the aria-modal dialog."""
    r = ui["trap"][fn]
    assert "__error" not in r, r
    assert r["left"] == [], (r["modal"], r["left"])


@pytest.mark.parametrize("fn", MODALS)
def test_escape_closes_a_modal_and_focus_goes_back_to_its_opener(ui, fn):
    """WCAG 2.2 SC 2.1.2 · SC 2.4.3 · SC 1.4.13: Escape closes the dialog (no keyboard trap) and focus returns to the control that opened it; a help pop-up open on the focused control takes the first Escape and leaves the dialog and focus alone."""
    r = ui["trap"][fn]
    if r.get("mark"):
        assert r.get("tip"), r   # Enter on a focused "?" mark opens its help
    if r.get("tip"):
        assert r.get("tipEscape") == {"tip": False, "modalOpen": True, "focusKept": True}, r
    assert r.get("back") == "c6Opener", r
    assert ui["trapErrors"] == []


def test_the_terraform_dialog_keeps_focus_when_it_redraws(ui):
    """WCAG 2.2 SC 2.4.3 · SC 2.1.1: ticking a pack with Space, or any redraw of the dialog, leaves focus on the same control inside the dialog, never on the page behind it."""
    r = ui["tfRedraw"]
    assert "__error" not in r, r
    assert r["tick"] == {"inDialog": True, "tag": "INPUT", "change": r["tick"]["change"], "checked": True, "same": True}, r
    assert r["redraw"]["inDialog"] and r["redraw"]["tag"] == "SUMMARY", r


def test_a_help_pop_up_in_a_modal_is_dismissed_first(ui):
    """WCAG 2.2 SC 1.4.13 · SC 2.1.2: the pop-up path above really ran: a "?" mark inside at least one modal opened its help with Enter, and its Escape was checked."""
    assert any(r.get("mark") and r.get("tip") and "tipEscape" in r for r in ui["trap"].values()), ui["trap"]


# ── UI token (ASVS V3, V2.10) ───────────────────────────────────────

@pytest.mark.parametrize("path", ["/report/todo", "/"])
def test_a_refused_token_is_asked_for_again_with_the_reason(locked, path):
    """ASVS V2.2.1 · V7.4.1 · CWE-755 · WSTG-ATHN-01 · WCAG 2.2 SC 3.3.1: a mistyped token re-opens the unlock dialog saying it was not accepted."""
    r = locked[path]
    assert "not accepted" in r.get("again", ""), r.get("__error")
    assert r["health"] == 200, "the right token on the second try unlocks the page"
    assert r["native"] == [] and r["errs"] == []


@pytest.mark.parametrize("path", ["/report/todo", "/"])
def test_the_unlock_field_is_a_password_field_with_focus(locked, path):
    """ASVS V2.1.11 (n/a) · V8.2.1 · CWE-549 · WCAG 2.2 SC 2.4.3: the token is typed into a masked, non-autocompleted field that has focus."""
    assert locked[path].get("field") == {"type": "password", "ac": "off", "focused": True}


@pytest.mark.parametrize("path", ["/report/todo", "/"])
def test_the_token_never_stays_in_the_page_storage_or_script_cookies(locked, path):
    """ASVS V3.4.2 · V3.4.3 · V8.2.2 · CWE-1004 · CWE-922 · WSTG-SESS-02: after unlocking, the token is only in an HttpOnly SameSite=Strict cookie."""
    r = locked[path]
    assert r.get("tokenInPage") is False and r["tokenInStorage"] is False
    assert r["cookies"] == [{"httpOnly": True, "sameSite": "Strict"}]


def test_unlock_stops_asking_after_three_refused_tokens(locked):
    """ASVS V2.2.1 · CWE-307 · CWE-400: three refused tokens, then the page stops asking (quiet period) instead of looping."""
    c = locked["capped"]
    assert c["asked"] == 3, c
    assert c["status"] == 401 and c["openAfter"] == 0
