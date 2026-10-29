// ── Simple mode (/simple) ─────────────────────────────────────────────
// The same app for someone with little Zscaler knowledge: seven big tasks,
// each a short wizard (one question per screen, "Step 2 of 4", Back and
// Next, a plain summary, one recommended next step and a link to the
// expert view). Nothing here is a new source of truth: every task calls the
// endpoints the expert pages call (/api/tenant/check, /api/assess,
// /api/path-analyzer/start, /api/dlp-packs, /api/report/docx ...), and
// anything that changes the tenant is handed to the expert page's own flow
// (Deploy policy packs with write mode and its preview, Review & remediate),
// never done from here.
//
// Every sentence the page shows lives in COPY below, so the readability
// test (tests/test_simple_mode.py) can measure it. In COPY, [[term]] or
// [[term|shown words]] is a word from glossary.js shown as a tap-to-explain
// chip, and {name} is a value filled in at run time.
(function () {
  'use strict';
  // COPY-START
  const COPY = {
    ui: {
      stepOf: 'Step {n} of {total}',
      back: 'Back',
      next: 'Next',
      done: 'Done',
      expert: 'Show me the expert view',
      stop: 'Stop',
      working: 'Working on it. Please wait.',
      looksOnly: 'This only looks. It changes nothing.',
      signInOnly: 'This only signs in. It reads nothing and changes nothing.',
      pickOne: 'Please pick one.',
      pickSome: 'Please pick at least one.',
      fillIn: 'Please fill this in: {what}.',
      needConn: 'First, connect your Zscaler.',
      needCheck: 'First, check how safe your data is.',
      needKey: 'Please connect again and type your secret key. We keep it only while this page is open.',
      stopped: 'You stopped it. Nothing was kept.',
      failed: 'Something went wrong. Here is what the app said:',
      tryAgain: 'Please try again, or open the expert view.',
      nextH: 'What should I do next?',
      expertTip: 'What an expert would do next',
      taskList: 'Back to all tasks',
      opensExpert: 'This opens the expert view.',
      keyAgain: 'You may need to type your secret key again there.',
      tagLook: 'Only looks',
      tagChange: 'Can change things, but only after you say yes',
    },
    lights: { good: 'Good', look: 'Needs a look', fix: 'Fix this' },
    conn: { none: 'Not connected yet', yes: 'Connected to {name}', here: 'the details saved on this computer' },
    home: {
      banner: 'New here? Try Simple mode',
    },
    tiles: {
      connect: { title: 'Connect my Zscaler', line: 'Sign in once, so this app can look at your settings.' },
      check: { title: 'Check how safe my data is', line: 'We look at your settings and give you a score.' },
      fix: { title: 'Fix the top problems', line: 'See the three most important things to fix, and how.' },
      protect: { title: 'Protect sensitive data', line: 'Add ready-made rules for the kind of work you do.' },
      path: { title: 'Why was something blocked?', line: 'Type a website, and we tell you what happens to it.' },
      changes: { title: 'Show what changed', line: 'See how your score moved, and what this app added.' },
      report: { title: 'Make a report for my boss', line: 'Get a Word file or an Excel table of your results.' },
    },
    connect: {
      how: {
        q: 'How do you want to connect?',
        saved: 'Use {name}',
        savedSub: 'A [[saved connection]] on this computer.',
        fresh: 'Set up a new connection',
        freshSub: 'You need three things from Zscaler. We show you where to find them.',
        server: 'Use the details saved on this computer',
        serverSub: 'Pick this if someone set up this computer for you.',
        sample: 'Try with a sample tenant',
        sampleSub: 'A made-up company, so you can look around first. Nothing here is real. See [[sample tenant]] and [[tenant]].',
      },
      where: {
        q: 'Where is your Zscaler?',
        intro: 'Your company has its own space in Zscaler, called a [[tenant]]. Let us find it.',
        pic1: 'Open the page where you sign in to Zscaler.',
        pic2: 'Look at the web address at the top.',
        pic3: 'The word before .zslogin.net is your short name.',
        cloudLabel: 'Which cloud do you use?',
        cloudHint: 'Not sure? Keep the first one. It works for most companies. See [[cloud]].',
        cloudMain: 'Most companies (pick this if you are not sure)',
        cloudGov: 'US government ({name})',
        vdLabel: 'Your short name',
        vdHint: 'This is your [[vanity domain]]. For acme.zslogin.net, type acme.',
      },
      key: {
        q: 'Find your app key',
        intro: 'This app needs its own login, called an [[api client|API client]]. You make it in [[zidentity|ZIdentity]].',
        pic1: 'Sign in to ZIdentity.',
        pic2: 'Click Integration, then API Clients.',
        pic3: 'Add a new client, or open the one you have.',
        pic4: 'Copy the Client ID and the Client Secret.',
        cidLabel: 'Client ID',
        cidHint: 'It is a long mix of letters and numbers. See [[client id|client ID]].',
        secLabel: 'Client secret',
        secHint: 'It is like a password, so keep it safe. See [[client secret]].',
      },
      secret: {
        q: 'Type your secret key',
        intro: 'This computer did not keep the secret key for {name}.',
        secLabel: 'Client secret',
        secHint: 'It is like a password. See [[client secret]]. We keep it only while this page is open.',
      },
      name: {
        q: 'Name this connection',
        orgLabel: 'Your company name',
        orgHint: 'We put it on your report.',
        whoLabel: 'Your name',
        whoHint: 'We put your name on the report, and on any rules you add later.',
        remember: 'Remember my secret key on this computer',
        rememberHint: 'Leave this off if other people use this computer.',
      },
      test: {
        q: 'Ready to sign in?',
        what: 'We will sign in to {name}.',
        go: 'Sign in',
        busy: 'Signing in. Please wait.',
        legacy: 'This saved connection uses the older sign-in. Please use the expert view for it.',
        sample: 'We will open the made-up company. Nothing you do there can touch a real [[tenant]].',
      },
      done: {
        q: 'You are connected!',
        ok: 'You are connected to {name}.',
        keyNote: 'We keep your secret key only while this page is open.',
        next: 'Next, check how safe your data is.',
        sampleNote: 'This company is made up. Nothing here is real. To use your own, connect again.',
      },
    },
    check: {
      conn: {
        q: 'Is this the right Zscaler?',
        yes: 'We will check {name}.',
        other: 'Want a different one? Use the Connect task first.',
      },
      what: {
        q: 'What should we look at?',
        intro: 'Pick the ways data can leave your company. Each way is a [[channel]].',
        web: 'Web uploads',
        webSub: 'Files and text that people send to websites.',
        endpoint: 'Computers',
        endpointSub: 'Files copied to USB sticks, printers and shared drives. This is an [[endpoint]] check.',
        email: 'Email',
        emailSub: 'Mail that goes out of Microsoft 365 or Gmail.',
        saas: 'Cloud apps',
        saasSub: 'Files kept in apps like Box or Google Drive. See [[saas|SaaS]].',
        scope: 'We read only what you pick. That is your [[scope]].',
      },
      go: {
        q: 'Ready to start?',
        time: 'It takes about one or two minutes.',
        btn: 'Start the check',
        progress: 'Checked {done} of {total}.',
      },
      result: {
        q: 'Here is your score',
        score: 'Your [[score]] is {score} out of 100.',
        noScore: 'We could not work out a score this time.',
        counts: 'We found {fail} things to fix and {review} things to look at.',
        none: 'We found nothing that needs a fix. Well done!',
        top: 'The most important one is this:',
        partial: 'Some checks could not run. Your [[api client|API client]] may need more rights.',
        nextFix: 'Next, fix the top problems.',
        nextProtect: 'Next, add ready-made rules to protect your data.',
      },
    },
    fix: {
      need: {
        q: 'Let us fix things',
        found: 'We found {fail} things to fix and {review} things to look at.',
        top: 'Here are the top {n}. We show them one at a time.',
        none: 'Good news! Nothing needs a fix right now.',
      },
      p: {
        q: 'Problem {n} of {total}',
        means: 'What this means',
        why: 'Why it matters',
        todo: 'What to do',
        fixed: 'When it is fixed:',
        more: 'More detail',
        fixBtn: 'Fix it step by step',
        fixNote: 'This opens the fix screen in the expert view. It shows the change first. Nothing changes until you say yes there.',
        packBtn: 'Add ready-made rules',
        packNote: 'Ready-made rules can fix this. We will help you pick them.',
        showBtn: 'Show me this in the expert view',
        showNote: 'The expert view shows all the details for this one.',
      },
      sum: {
        q: 'Your top problems',
        line: 'Start with the first one. Then check again to see your score go up.',
        none: 'There is nothing to fix. Your data is in good shape.',
        next: 'Fix the first problem. Then check again to see your score go up.',
      },
    },
    protect: {
      kind: {
        q: 'What kind of work does your company do?',
        intro: 'We use this to pick the right rules for you.',
      },
      pack: {
        q: 'Pick a rule set',
        intro: 'A ready-made rule set is called a [[policy pack]]. These fit your kind of work.',
        first: 'Best first pick',
      },
      preview: {
        q: 'Here is what it adds',
        lists: '{n} word lists that spot private data. Each one is a [[dictionary]].',
        engines: '{n} [[engine|engines]] that mix the lists into tests.',
        rules: '{n} [[rule|rules]] that say what to do when a test matches.',
        off: 'Every rule starts turned off. When you turn one on, it only watches at first. It is [[monitor-only]].',
        keep: 'Nothing you have now is changed or taken away.',
      },
      sum: {
        q: 'Ready to add it?',
        pick: 'You picked {pack} for {kind}.',
        adds: 'It adds {total} items to your Zscaler.',
        nothingYet: 'Nothing has changed yet.',
        warnH: 'This will change your Zscaler.',
        warn1: 'Nothing changes until you turn on [[write mode]] and type the [[safety words]].',
        warn2: 'Then you see the full plan. You press [[deploy|Deploy]] only if you like it.',
        btn: 'Open the deploy screen',
        askT: 'Open the deploy screen?',
        askB: 'We take you to the expert view with this rule set picked. Nothing changes yet.',
        askOk: 'Yes, open it',
        next: 'After you add the rules, check how safe your data is again.',
      },
    },
    path: {
      site: {
        q: 'Which website?',
        label: 'Website address',
        hint: 'For example: dropbox.com or drive.google.com',
      },
      where: {
        q: 'Where should we look?',
        intro: 'Pick the kinds of rules to read. We read only what you pick. That is your [[scope]].',
        web: 'Web rules',
        webSub: 'Rules that stop some websites or apps. This covers [[url filtering|URL filtering]], [[cloud app control|Cloud App Control]] and [[ssl inspection|SSL inspection]].',
        data: 'Data rules',
        dataSub: 'Rules that look for private data. This is [[dlp|DLP]].',
        app: 'The Zscaler app',
        appSub: 'The [[client connector|Client Connector]] app on each computer.',
      },
      go: {
        q: 'Ready to look?',
        time: 'The first look takes about a minute. After that it is quick.',
        btn: 'Find out',
        wait: 'Looking. {secs} seconds so far.',
      },
      answer: {
        q: 'Here is the answer',
        blocked: 'Yes. Zscaler blocks {host}.',
        blockedBy: 'The rule that blocks it is called {rule}.',
        bypassed: 'Zscaler does not check {host} at all. The traffic goes around Zscaler. That is a [[bypass]].',
        blind: 'Zscaler lets {host} through, but it cannot see inside. The traffic is [[encrypted]].',
        enforce: 'Zscaler lets {host} through and checks it. It can stop private data from going there.',
        monitor: 'Zscaler lets {host} through and watches it. It does not stop anything there.',
        none: 'Zscaler lets {host} through. No data rule looks at it.',
        unknown: 'We could not find out for sure. Some rules could not be read.',
        outOfScope: 'Zscaler lets {host} through. We did not read the data rules, because you left them out.',
        conditional: 'Zscaler lets {host} through. The data rules depend on who the person is.',
        metadataOnly: 'Zscaler lets {host} through. No rule here looks inside the files.',
        notBlocked: 'So Zscaler does not block it here. A block may come from some other place.',
        exact: 'The exact answer',
        ifWrong: 'If {host} should work, show this to your Zscaler admin.',
        next: 'Want to know more? Check how safe your data is.',
      },
    },
    changes: {
      what: {
        q: 'What do you want to see?',
        score: 'How my score changed',
        scoreSub: 'Compare your last two check-ups.',
        added: 'What this app added',
        addedSub: 'Rule sets that this app put into your Zscaler.',
      },
      show: {
        q: 'Here is what changed',
        needSaved: 'We keep a score history only for a [[saved connection]]. Please connect with one first.',
        none: 'You have no check-ups yet.',
        one: 'You have only one [[check-up]] so far. Do another one later to compare.',
        moved: 'Your score went from {a} to {b}.',
        up: 'That is better. Nice work!',
        same: 'It stayed the same.',
        down: 'That is lower than before. Let us find out why.',
        fails: 'Problems to fix went from {a} to {b}.',
        histH: 'Your last check-ups',
        colWhen: 'When',
        colScore: 'Score',
        colFix: 'To fix',
        noDeploys: 'This app has not added anything to your Zscaler yet.',
        deploy: 'On {when}, this app added {n} items from {packs}.',
        undone: 'Later, {n} of them were taken out again.',
        next: 'Next, check how safe your data is today.',
      },
    },
    report: {
      kind: {
        q: 'Which kind of file?',
        word: 'A Word file',
        wordSub: 'A neat report to read or print.',
        sheet: 'A spreadsheet',
        sheetSub: 'A table that you can open in Excel. See [[spreadsheet]].',
      },
      sum: {
        q: 'Make your report',
        about: 'Your report is about {org}. The score is {score} out of 100.',
        btn: 'Make my file',
        busy: 'Making your file. Please wait.',
        made: 'Your file is ready. Look in your Downloads folder.',
        share: 'Send it to your boss. It shows the score and what to fix.',
        next: 'Next, fix the top problems, so the next report looks even better.',
      },
    },
  };
  // COPY-END

  // ── Small helpers ───────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const GLOSS = window.SIMPLE_GLOSSARY || {};
  let defSeq = 0;
  // COPY text to HTML: escaped, [[term]] chips, then {name} values (escaped).
  function rich(s, vars) {
    let h = E(s).replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (m, key, shown) => chip(key, shown || key));
    if (vars) h = h.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? E(vars[k]) : m));
    return h;
  }
  function chip(key, shown) {
    const k = String(key).toLowerCase();
    if (!GLOSS[k]) return E(shown);
    const id = `smDef${++defSeq}`;
    return `<button type="button" class="sm-term" data-term="${E(k)}" aria-expanded="false" aria-controls="${id}">${E(shown)}</button><span class="sm-def" id="${id}" role="note" hidden>${E(GLOSS[k].def)}</span>`;
  }
  // Plain text (no chips), for button labels and attributes.
  function plain(s, vars) {
    let t = String(s).replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (m, key, shown) => shown || key);
    if (vars) t = t.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
    return t;
  }
  // A traffic light: the colour AND the word, never colour alone.
  function light(kind) {
    const k = kind === 'good' || kind === 'fix' ? kind : 'look';
    return `<span class="sm-light ${k}"><span class="sm-dot" aria-hidden="true"></span>${E(COPY.lights[k])}</span>`;
  }
  function icon(name) { return (window.dlpIcon ? window.dlpIcon(name, 26) : ''); }
  function say(t) { const l = $('smLive'); if (!l) return; l.textContent = ''; setTimeout(() => { l.textContent = t; }, 30); }
  function store(kind) { try { return kind === 'session' ? window.sessionStorage : window.localStorage; } catch (e) { return null; } }
  function readJSON(kind, key) { try { const s = store(kind); const raw = s && s.getItem(key); return raw ? JSON.parse(raw) : null; } catch (e) { return null; } }
  function writeJSON(kind, key, v) { try { const s = store(kind); if (s) s.setItem(key, JSON.stringify(v)); } catch (e) { /* storage blocked: the page still works */ } }
  function writeRaw(key, v) { try { const s = store('local'); if (s) s.setItem(key, v); } catch (e) { /* storage blocked */ } }

  // The server's reason for a refusal (FastAPI's {"detail": ...}), as text.
  async function reason(r) {
    let d = '';
    try {
      const j = await r.json();
      d = j && j.detail;
      if (Array.isArray(d)) d = d.map(x => (x && x.msg) || '').filter(Boolean).join('; ');
      else if (d && typeof d === 'object') d = [d.cause, d.fix].filter(Boolean).join(' ') || d.message || '';
    } catch (e) { d = ''; }
    return String(d || '').trim() || `HTTP ${r.status}`;
  }
  async function getJSON(url) {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(await reason(r));
    return r.json();
  }
  async function postJSON(url, body, headers) {
    const r = await fetch(url, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: JSON.stringify(body || {}) });
    if (!r.ok) throw new Error(await reason(r));
    return r.json();
  }
  function errBox(msg) {
    return `<div class="sm-err" role="alert"><p>${light('fix')} ${E(COPY.ui.failed)}</p><p>${E(msg)}</p><p>${E(COPY.ui.tryAgain)}</p></div>`;
  }

  // ── State ───────────────────────────────────────────────────────
  // The connection (never the secret) is remembered per browser; a typed
  // secret lives only in this page's memory. The last assessment result is
  // kept in this tab's sessionStorage under the same key the assessment
  // page restores from, so "Show me the expert view" opens on it.
  const LS_CONN = 'zsimple_conn';
  const LS_MODE = 'zsimple_mode';
  const SS_RESULTS = 'zassess_last_results';
  const S = { conn: readJSON('local', LS_CONN), secret: '', report: readJSON('session', SS_RESULTS), catalog: null };
  function setConn(c) { S.conn = c; writeJSON('local', LS_CONN, c); if (c && c.kind === 'profile' && c.id) writeRaw('zassess_profile', c.id); renderConn(); }
  function needsKey() { return !!(S.conn && S.conn.kind === 'profile' && !S.conn.has_secret && !S.secret); }
  function credBody() {
    if (!S.conn) return {};
    if (S.conn.kind === 'profile') return S.secret ? { profile_id: S.conn.id, client_secret: S.secret } : { profile_id: S.conn.id };
    return {};
  }
  // A remembered sample connection holds only while the server still uses the sample for this browser.
  if (S.conn && S.conn.kind === 'sample') getJSON('/api/offline/status').then(d => { if (!d || d.mode !== 'sample') setConn(null); }).catch(() => {});
  function connName() { return S.conn ? (S.conn.kind === 'server' ? (S.conn.name || COPY.conn.here) : S.conn.name) : ''; }
  function renderConn() {
    const el = $('smConn'); if (!el) return;
    el.innerHTML = S.conn ? `${light('good')} ${E(plain(COPY.conn.yes, { name: connName() }))}` : `${light('look')} ${E(COPY.conn.none)}`;
  }
  function saveReport(rep) {
    S.report = rep;
    try { const s = store('session'); if (s) s.setItem(SS_RESULTS, JSON.stringify(rep)); } catch (e) { /* too large or blocked: kept in memory */ }
  }
  function counts(rep) {
    const ch = ((rep && rep.checks) || []).filter(c => !c.out_of_scope);
    return { fail: ch.filter(c => c.status === 'FAIL').length, review: ch.filter(c => c.status === 'REVIEW').length };
  }
  function topFindings(rep, n) {
    const ch = ((rep && rep.checks) || []).filter(c => !c.out_of_scope);
    return ch.filter(c => c.status === 'FAIL').concat(ch.filter(c => c.status === 'REVIEW')).slice(0, n || 3);
  }
  function scoreLight(score) { return score == null ? 'look' : score >= 75 ? 'good' : score >= 50 ? 'look' : 'fix'; }

  // Expert page deep links (the assessment page reads ?simple=...).
  const EXPERT = {
    connect: '/?simple=connect', check: '/', fix: '/', protect: '/?simple=deploy', path: '/report/path', changes: '/?simple=connect', report: '/',
  };
  // Which explain.js entry each task belongs to (its `next` is the expert tip).
  const EXPLAIN = { connect: 'connect', check: 'results', fix: 'remediate', protect: 'packs', path: 'path', changes: 'assessment', report: 'results' };
  const ICONS = { connect: 'plug', check: 'shield', fix: 'wrench', protect: 'box', path: 'compass', changes: 'repeat', report: 'doc' };
  const CHANGES = { fix: true, protect: true };

  // ── Building blocks for steps ───────────────────────────────────
  // Big radio / check cards. The sub-line sits outside the <label> (a chip
  // is a button, and a label may not hold one) and describes the input.
  let optSeq = 0;
  function choices(name, legend, opts, multi, chosen) {
    const type = multi ? 'checkbox' : 'radio';
    const items = opts.map(o => {
      const on = multi ? !!(chosen && chosen[o.value]) : chosen === o.value;
      const id = `smOpt${++optSeq}`;
      return `<div class="sm-opt"><input type="${type}" id="${id}" name="${E(name)}" value="${E(o.value)}" ${on ? 'checked' : ''}${o.sub ? ` aria-describedby="${id}S"` : ''}><div class="sm-ob"><label class="sm-ot" for="${id}">${o.html || E(o.title)}</label>${o.sub ? `<span class="sm-os" id="${id}S">${o.sub}</span>` : ''}</div></div>`;
    }).join('');
    return `<fieldset class="sm-choices"><legend class="sr-only">${E(legend)}</legend>${items}</fieldset>`;
  }
  function picked(name) { const el = document.querySelector(`input[name="${name}"]:checked`); return el ? el.value : ''; }
  function pickedAll(name) { const out = {}; document.querySelectorAll(`input[name="${name}"]`).forEach(el => { out[el.value] = el.checked; }); return out; }
  function field(id, label, hint, attrs) {
    return `<div class="sm-field"><label for="${id}">${E(label)}</label><input id="${id}" ${attrs || 'type="text"'} aria-describedby="${id}H" autocomplete="off" spellcheck="false"><span class="sm-hint" id="${id}H">${hint}</span></div>`;
  }
  function pics(list) { return `<ol class="sm-pics">${list.map(([ic, t]) => `<li><span class="sm-pi" aria-hidden="true">${icon(ic)}</span><span>${E(t)}</span></li>`).join('')}</ol>`; }
  function safeBox(text) { return `<div class="sm-box safe"><p>${light('good')} ${rich(text)}</p></div>`; }
  function val(id) { return (($(id) || {}).value || '').trim(); }
  function setVal(id, v) { const el = $(id); if (el && v != null) el.value = v; }

  // ── The wizards ─────────────────────────────────────────────────
  // A step: { id, skip(st), q(st) (the question), render(st) → HTML,
  // after(st) (wire up), check(st) → error text, next(st, ui) → true to go
  // on, nextLabel, final }. The last step is the summary.
  const W = {};

  // 1. Connect my Zscaler
  const CC = COPY.connect;
  W.connect = {
    steps: [
      { id: 'how', q: () => CC.how.q,
        load: async st => { if (!st.profiles) { try { st.profiles = ((await getJSON('/api/tenant-profiles')).profiles || []); } catch (e) { st.profiles = []; } } },
        render: st => choices('smHow', CC.how.q, [
          ...(st.profiles || []).map(p => ({ value: `profile:${p.id}`, title: plain(CC.how.saved, { name: p.name || p.vanity_domain || p.id }), sub: rich(CC.how.savedSub) })),
          { value: 'new', title: CC.how.fresh, sub: rich(CC.how.freshSub) },
          { value: 'server', title: CC.how.server, sub: rich(CC.how.serverSub) },
          { value: 'sample', title: CC.how.sample, sub: rich(CC.how.sampleSub) },
        ], false, st.how),
        check: st => { st.how = picked('smHow'); return st.how ? '' : COPY.ui.pickOne; },
        next: async st => { await lookupProfile(st); return true; } },
      { id: 'where', skip: st => (st.how || 'new') !== 'new', q: () => CC.where.q,
        render: st => `<p>${rich(CC.where.intro)}</p>${pics([['globe', CC.where.pic1], ['search', CC.where.pic2], ['key', CC.where.pic3]])}
          <div class="sm-field"><label for="smCloud">${E(CC.where.cloudLabel)}</label><select id="smCloud" aria-describedby="smCloudH">
            <option value="production">${E(CC.where.cloudMain)}</option>
            <option value="zscalergov">${E(plain(CC.where.cloudGov, { name: 'zscalergov.net' }))}</option>
            <option value="zscalergovus">${E(plain(CC.where.cloudGov, { name: 'zscalergov.us' }))}</option>
            ${['zscaler', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zscloud', 'zscalerten', 'zscalerbeta'].map(c => `<option value="${c}">${c}.net</option>`).join('')}
          </select><span class="sm-hint" id="smCloudH">${rich(CC.where.cloudHint)}</span></div>
          ${field('smVd', CC.where.vdLabel, rich(CC.where.vdHint))}`,
        after: st => { setVal('smCloud', st.cloud || 'production'); setVal('smVd', st.vd); },
        check: st => {
          st.cloud = val('smCloud') || 'production';
          // Someone may paste the whole address: keep the short name only.
          st.vd = val('smVd').replace(/^https?:\/\//i, '').split(/[./]/)[0];
          return st.vd ? '' : plain(COPY.ui.fillIn, { what: CC.where.vdLabel });
        } },
      { id: 'key', skip: st => (st.how || 'new') !== 'new', q: () => CC.key.q,
        render: () => `<p>${rich(CC.key.intro)}</p>${pics([['lock', CC.key.pic1], ['gear', CC.key.pic2], ['plug', CC.key.pic3], ['clipboard', CC.key.pic4]])}
          ${field('smCid', CC.key.cidLabel, rich(CC.key.cidHint))}${field('smSec', CC.key.secLabel, rich(CC.key.secHint), 'type="password"')}`,
        after: st => { setVal('smCid', st.cid); setVal('smSec', st.sec); },
        check: st => {
          st.cid = val('smCid'); st.sec = val('smSec');
          if (!st.cid) return plain(COPY.ui.fillIn, { what: CC.key.cidLabel });
          return st.sec ? '' : plain(COPY.ui.fillIn, { what: CC.key.secLabel });
        } },
      { id: 'secret', skip: st => !(st.profile && !st.profile.has_secret && st.profile.auth_method !== 'legacy'), q: () => CC.secret.q,
        render: st => `<p>${rich(CC.secret.intro, { name: st.profile.name })}</p>${field('smSec2', CC.secret.secLabel, rich(CC.secret.secHint), 'type="password"')}`,
        check: st => { st.sec = val('smSec2'); return st.sec ? '' : plain(COPY.ui.fillIn, { what: CC.secret.secLabel }); } },
      { id: 'name', skip: st => (st.how || 'new') !== 'new' && st.how !== 'server', q: () => CC.name.q,
        render: st => `${field('smOrg', CC.name.orgLabel, rich(CC.name.orgHint))}${field('smWho', CC.name.whoLabel, rich(CC.name.whoHint))}
          ${st.how === 'new' ? choices('smRemember', CC.name.remember, [{ value: 'yes', title: CC.name.remember, sub: rich(CC.name.rememberHint) }], true, { yes: !!st.remember }) : ''}`,
        after: st => { setVal('smOrg', st.org); setVal('smWho', st.who); },
        check: st => {
          st.org = val('smOrg'); st.who = val('smWho'); st.remember = !!pickedAll('smRemember').yes;
          if (st.how === 'new' && !st.org) return plain(COPY.ui.fillIn, { what: CC.name.orgLabel });
          return '';
        } },
      { id: 'test', q: () => CC.test.q, nextLabel: CC.test.go,
        render: st => {
          if (st.profile && st.profile.auth_method === 'legacy') return `<p>${light('look')} ${E(CC.test.legacy)}</p>`;
          if (st.how === 'sample') return `<p>${rich(CC.test.sample)}</p>${safeBox(COPY.ui.looksOnly)}<div id="smRun" role="status" aria-live="polite"></div>`;
          const name = st.how === 'new' ? (st.org || st.vd) : st.how === 'server' ? COPY.conn.here : st.profile.name;
          return `<p>${rich(CC.test.what, { name })}</p>${safeBox(COPY.ui.signInOnly)}<div id="smRun" role="status" aria-live="polite"></div>`;
        },
        check: st => (st.profile && st.profile.auth_method === 'legacy') ? CC.test.legacy : '',
        next: async st => {
          const run = $('smRun'); if (run) run.textContent = CC.test.busy;
          if (st.how === 'sample') {
            // The sample tenant (offline_tenant.py): the server answers every read from it, for this browser.
            const d = await postJSON('/api/offline/sample', {});
            setConn({ kind: 'sample', name: d.company || d.tenant_label || 'Sample', org: d.company || '', who: '' });
            return true;
          }
          // Any real connection: leave the sample or a snapshot first.
          await postJSON('/api/offline/leave', {});
          if (st.how === 'new') {
            const creds = { auth_method: 'oneapi', cloud: st.cloud, vanity_domain: st.vd, client_id: st.cid, client_secret: st.sec };
            const ok = await postJSON('/api/tenant/check', creds);
            // Signed in: save the details as a profile (a file on this computer, never the tenant).
            const prof = await postJSON('/api/tenant-profiles', Object.assign({ name: st.org || st.vd, org_name: st.org, assessor: st.who, remember_secret: !!st.remember }, creds));
            S.secret = st.sec;
            st.label = ok.tenant_label || st.vd;
            st.warning = prof.secret_warning || '';
            setConn({ kind: 'profile', id: prof.id, name: prof.name || st.org || st.vd, has_secret: !!prof.has_secret, org: st.org, who: st.who });
          } else if (st.how === 'server') {
            const ok = await postJSON('/api/tenant/check', {});
            setConn({ kind: 'server', name: ok.tenant_label || '', org: st.org, who: st.who });
          } else {
            const body = { profile_id: st.profile.id };
            if (st.sec) body.client_secret = st.sec;
            await postJSON('/api/tenant/check', body);
            S.secret = st.sec || '';
            setConn({ kind: 'profile', id: st.profile.id, name: st.profile.name, has_secret: !!st.profile.has_secret, org: st.profile.org_name || '', who: st.profile.assessor || '' });
          }
          return true;
        } },
      { id: 'done', final: true, q: () => CC.done.q,
        render: st => `<p class="sm-row">${light('good')} <span>${rich(CC.done.ok, { name: connName() })}</span></p>
          ${S.conn && S.conn.kind === 'profile' && !S.conn.has_secret ? `<p>${rich(CC.done.keyNote)}</p>` : ''}
          ${S.conn && S.conn.kind === 'sample' ? `<p>${rich(CC.done.sampleNote)}</p>` : ''}
          ${st.warning ? `<p class="sm-dim">${E(st.warning)}</p>` : ''}`,
        nextStep: () => ({ text: CC.done.next, tile: 'check' }) },
    ],
  };
  // A saved profile's own details (is a secret remembered? which sign-in?),
  // looked up when it is picked, so the secret step knows whether to show.
  async function lookupProfile(st) {
    st.profile = null;
    if (!st.how || !st.how.startsWith('profile:')) return;
    const id = st.how.slice(8);
    try { st.profile = await getJSON(`/api/tenant-profiles/${encodeURIComponent(id)}`); } catch (e) { st.profile = (st.profiles || []).find(p => p.id === id) || { id, name: id }; }
  }

  // 2. Check how safe my data is
  const CK = COPY.check;
  const CHANNELS = [['web', 'web_dlp'], ['endpoint', 'endpoint_dlp'], ['email', 'email_dlp'], ['saas', 'saas_casb']];
  function connStep(text) {
    return { id: 'conn', q: () => CK.conn.q,
      render: () => S.conn && !needsKey()
        ? `<p class="sm-row">${light('good')} <span>${rich(text || CK.conn.yes, { name: connName() })}</span></p><p class="sm-dim">${rich(CK.conn.other)}</p>`
        : `<p class="sm-row">${light('look')} <span>${rich(needsKey() ? COPY.ui.needKey : COPY.ui.needConn)}</span></p><p><button type="button" class="sm-btn primary" data-tile="connect">${E(COPY.tiles.connect.title)}</button></p>`,
      check: () => (!S.conn ? COPY.ui.needConn : needsKey() ? COPY.ui.needKey : '') };
  }
  W.check = {
    steps: [
      connStep(),
      { id: 'what', q: () => CK.what.q,
        render: st => `<p>${rich(CK.what.intro)}</p>${choices('smCh', CK.what.q, CHANNELS.map(([k]) => ({ value: k, title: CK.what[k], sub: rich(CK.what[k + 'Sub']) })), true, st.ch || { web: true })}
          ${safeBox(CK.what.scope + ' ' + COPY.ui.looksOnly)}`,
        check: st => { st.ch = pickedAll('smCh'); return Object.values(st.ch).some(Boolean) ? '' : COPY.ui.pickSome; } },
      { id: 'go', q: () => CK.go.q, nextLabel: CK.go.btn,
        render: () => `<p>${rich(CK.go.time)}</p>${safeBox(COPY.ui.looksOnly)}
          <div id="smRun" hidden><div class="sm-meter" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="${E(CK.go.btn)}"><span id="smRunBar" style="width:0%"></span></div>
          <p id="smRunText" role="status" aria-live="polite"></p></div>`,
        next: (st, ui) => runAssessment(st, ui) },
      { id: 'result', final: true, q: () => CK.result.q,
        render: () => {
          const rep = S.report || {}; const c = counts(rep); const sc = rep.score;
          const top = topFindings(rep, 1)[0];
          const sum = rep.summary || {};
          return `<div class="sm-row"><span class="sm-big">${sc == null ? '–' : E(Math.round(sc))}</span>${light(scoreLight(sc))}</div>
            <p>${sc == null ? rich(CK.result.noScore) : rich(CK.result.score, { score: Math.round(sc) })}</p>
            <p>${c.fail + c.review ? rich(CK.result.counts, c) : rich(CK.result.none)}</p>
            ${top ? `<div class="sm-box"><p>${E(CK.result.top)}</p><p class="sm-row">${light(top.status === 'FAIL' ? 'fix' : 'look')} <strong>${E(top.label)}</strong></p></div>` : ''}
            ${sum.not_permitted ? `<p>${light('look')} ${rich(CK.result.partial)}</p>` : ''}`;
        },
        nextStep: () => (counts(S.report).fail + counts(S.report).review ? { text: CK.result.nextFix, tile: 'fix' } : { text: CK.result.nextProtect, tile: 'protect' }) },
    ],
  };

  // The assessment: the same POST /api/assess stream the assessment page
  // reads, with the channels picked here as the scope (DLP only).
  async function runAssessment(st, ui) {
    const channels = {};
    CHANNELS.forEach(([k, id]) => { if (st.ch && st.ch[k]) channels[id] = 'zscaler'; });
    const body = Object.assign({ scopes: ['dlp'], channels, org_name: (S.conn && S.conn.org) || (S.conn && S.conn.name) || 'Unknown', assessor: (S.conn && S.conn.who) || 'Unknown' }, credBody());
    const box = $('smRun'), bar = $('smRunBar'), txt = $('smRunText');
    if (box) box.hidden = false;
    const ac = new AbortController();
    ui.onStop(() => ac.abort());
    let report = null, failure = '';
    try {
      const r = await fetch('/api/assess', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: ac.signal });
      if (!r.ok) throw new Error(await reason(r));
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let cut;
        while ((cut = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, cut); buf = buf.slice(cut + 2);
          let ev = '', data = '';
          chunk.split('\n').forEach(l => { if (l.startsWith('event: ')) ev = l.slice(7); else if (l.startsWith('data: ')) data += l.slice(6); });
          if (!ev || !data) continue;
          let d = null; try { d = JSON.parse(data); } catch (e) { continue; }
          if (ev === 'progress' && d.total) {
            const pct = Math.max(0, Math.min(100, Number(d.pct) || 0));
            if (bar) bar.style.width = pct + '%';
            const m = bar && bar.parentElement; if (m) m.setAttribute('aria-valuenow', String(pct));
            if (txt) txt.textContent = plain(CK.go.progress, { done: d.completed || 0, total: d.total });
          } else if (ev === 'complete') {
            report = d;
          } else if (ev === 'journey' && report) {
            report.journey = d.journey; if (d.profile) report.profile = d.profile;
          } else if (ev === 'error') {
            failure = d.message || '';
          }
        }
      }
    } catch (e) {
      if (e && e.name === 'AbortError') { ui.error(COPY.ui.stopped); return false; }
      failure = String((e && e.message) || e);
    }
    if (!report) { ui.error(failure || COPY.ui.failed); return false; }
    saveReport(report);
    return true;
  }

  // 3. Fix the top problems
  const CF = COPY.fix;
  async function loadCatalog() {
    if (S.catalog) return S.catalog;
    try { S.catalog = (await getJSON('/api/remediation/catalog')).catalog || []; } catch (e) { S.catalog = []; }
    return S.catalog;
  }
  // The same matcher the assessment page uses (_findRecipeForCheck).
  function recipeFor(id) {
    const cat = S.catalog || [];
    return cat.find(r => r.check_id === id) || cat.find(r => (r.checks || []).includes(id)) || cat.find(r => id && id.startsWith(r.check_id)) || null;
  }
  // The first sentence of a server explanation; the rest folds under "More detail".
  function firstSentence(t) { const m = String(t || '').match(/^(.+?[.!?])(\s|$)/); return m ? m[1] : String(t || ''); }
  function fixAction(f) {
    if (recipeFor(f.id)) return { kind: 'expert', label: CF.p.fixBtn, note: CF.p.fixNote, href: `/?simple=fix&check=${encodeURIComponent(f.id)}` };
    if (/dlp/i.test(String(f.section || ''))) return { kind: 'tile', label: CF.p.packBtn, note: CF.p.packNote, tile: 'protect' };
    return { kind: 'expert', label: CF.p.showBtn, note: CF.p.showNote, href: `/?simple=finding&check=${encodeURIComponent(f.id)}` };
  }
  function problemStep(i) {
    return { id: `p${i}`, skip: () => !topFindings(S.report, 3)[i], q: () => plain(CF.p.q, { n: i + 1, total: topFindings(S.report, 3).length }),
      render: () => {
        const f = topFindings(S.report, 3)[i]; const p = f.plain || {}; const a = fixAction(f);
        return `<p class="sm-row">${light(f.status === 'FAIL' ? 'fix' : 'look')} <strong>${E(f.label)}</strong></p>
          <div class="sm-box"><h3>${E(CF.p.means)}</h3><p>${E(p.found || f.detail || '')}</p></div>
          ${p.outcome || p.means ? `<div class="sm-box"><h3>${E(CF.p.why)}</h3><p>${p.outcome ? `${E(CF.p.fixed)} ${E(p.outcome)}` : E(firstSentence(p.means))}</p></div>` : ''}
          ${p.do ? `<div class="sm-box"><h3>${E(CF.p.todo)}</h3><p>${E(firstSentence(p.do))}</p></div>` : ''}
          ${p.means || p.do ? `<details class="sm-box"><summary>${E(CF.p.more)}</summary>${p.means ? `<p class="sm-dim">${E(p.means)}</p>` : ''}${p.do ? `<p class="sm-dim">${E(p.do)}</p>` : ''}</details>` : ''}
          <div class="sm-box ${a.kind === 'expert' ? 'warn' : 'nextstep'}"><p>${rich(a.note)}</p>${a.kind === 'expert' ? `<p class="sm-dim">${rich(COPY.ui.keyAgain)}</p>` : ''}
            <p>${a.kind === 'expert' ? `<a class="sm-btn primary" href="${E(a.href)}">${E(a.label)}</a>` : `<button type="button" class="sm-btn primary" data-tile="${E(a.tile)}">${E(a.label)}</button>`}</p></div>`;
      } };
  }
  W.fix = {
    steps: [
      { id: 'need', q: () => CF.need.q,
        load: () => loadCatalog(),
        render: () => {
          if (!S.report) return `<p class="sm-row">${light('look')} <span>${rich(COPY.ui.needCheck)}</span></p><p><button type="button" class="sm-btn primary" data-tile="check">${E(COPY.tiles.check.title)}</button></p>`;
          const c = counts(S.report); const n = topFindings(S.report, 3).length;
          return n ? `<p>${rich(CF.need.found, c)}</p><p>${rich(CF.need.top, { n })}</p>` : `<p class="sm-row">${light('good')} <span>${rich(CF.need.none)}</span></p>`;
        },
        check: () => (S.report ? '' : COPY.ui.needCheck) },
      problemStep(0), problemStep(1), problemStep(2),
      { id: 'sum', final: true, q: () => CF.sum.q,
        render: () => {
          const top = topFindings(S.report, 3);
          if (!top.length) return `<p class="sm-row">${light('good')} <span>${rich(CF.sum.none)}</span></p>`;
          return `<ol class="sm-list">${top.map(f => `<li><span class="sm-row">${light(f.status === 'FAIL' ? 'fix' : 'look')} <span>${E(f.label)}</span></span></li>`).join('')}</ol><p>${rich(CF.sum.line)}</p>`;
        },
        nextStep: () => {
          const f = topFindings(S.report, 3)[0];
          if (!f) return { text: COPY.check.result.nextProtect, tile: 'protect' };
          const a = fixAction(f);
          return a.kind === 'tile' ? { text: CF.sum.next, tile: a.tile } : { text: CF.sum.next, href: a.href, label: a.label };
        } },
    ],
  };

  // 4. Protect sensitive data
  const CP = COPY.protect;
  W.protect = {
    steps: [
      { id: 'kind', q: () => CP.kind.q,
        load: async st => { if (!st.industries) { try { st.industries = (await getJSON('/api/vertical-scope')).industries || []; } catch (e) { st.industries = []; st.loadError = String(e.message || e); } } },
        render: st => (st.loadError ? errBox(st.loadError) : '') + `<p>${rich(CP.kind.intro)}</p>` + choices('smKind', CP.kind.q, (st.industries || []).map(i => ({ value: i, title: i })), false, st.kind),
        check: st => { st.kind = picked('smKind'); return st.kind ? '' : COPY.ui.pickOne; } },
      { id: 'pack', q: () => CP.pack.q,
        load: async st => {
          if (st.scopeFor === st.kind) return;
          const sc = await getJSON(`/api/vertical-scope?industry=${encodeURIComponent(st.kind)}`);
          let all = []; try { all = (await getJSON('/api/dlp-packs')).packs || []; } catch (e) { all = []; }
          const ids = (sc.industry_packs && sc.industry_packs.length ? sc.industry_packs : sc.packs) || [];
          st.packs = ids.map(id => all.find(p => p.id === id) || { id, name: id }).filter(Boolean);
          st.scopeFor = st.kind;
          if (!st.packs.some(p => p.id === st.pack)) st.pack = st.packs.length ? st.packs[0].id : '';
        },
        render: st => `<p>${rich(CP.pack.intro)}</p>` + choices('smPack', CP.pack.q, (st.packs || []).map((p, i) => ({
          value: p.id, html: `${E(p.name || p.id)}${i === 0 ? ` <span class="sm-dim">· ${E(CP.pack.first)}</span>` : ''}`, sub: E(p.description || ''),
        })), false, st.pack),
        check: st => { st.pack = picked('smPack'); return st.pack ? '' : COPY.ui.pickOne; } },
      { id: 'preview', q: () => CP.preview.q,
        load: async st => { if (st.detailFor !== st.pack) { st.detail = await getJSON(`/api/dlp-packs/${encodeURIComponent(st.pack)}`); st.detailFor = st.pack; } },
        render: st => {
          const d = st.detail || {};
          const n = k => ((d[k] || {}).total) || 0;
          return `<ul class="sm-list">
            <li>${rich(CP.preview.lists, { n: n('dictionaries') })}</li>
            <li>${rich(CP.preview.engines, { n: n('engines') })}</li>
            <li>${rich(CP.preview.rules, { n: n('policies') })}</li></ul>
            <p>${rich(CP.preview.off)}</p><p>${rich(CP.preview.keep)}</p>${safeBox(COPY.ui.looksOnly)}`;
        } },
      { id: 'sum', final: true, q: () => CP.sum.q,
        render: st => {
          const d = st.detail || {}; const p = (st.packs || []).find(x => x.id === st.pack) || { name: st.pack };
          const total = ['dictionaries', 'engines', 'policies'].reduce((a, k) => a + (((d[k] || {}).total) || 0), 0);
          return `<p>${rich(CP.sum.pick, { pack: p.name || st.pack, kind: st.kind })}</p><p>${rich(CP.sum.adds, { total })}</p>
            <p class="sm-row">${light('good')} <span>${rich(CP.sum.nothingYet)}</span></p>
            <div class="sm-box warn"><h3>${light('look')} ${E(CP.sum.warnH)}</h3><p>${rich(CP.sum.warn1)}</p><p>${rich(CP.sum.warn2)}</p>
              <p class="sm-dim">${rich(COPY.ui.keyAgain)}</p>
              <p><button type="button" class="sm-btn primary" id="smDeployGo">${E(CP.sum.btn)}</button></p></div>`;
        },
        after: st => {
          const b = $('smDeployGo'); if (!b) return;
          b.addEventListener('click', async () => {
            let ok = true;
            if (window.dlpDialog && window.dlpDialog.ask) ok = await window.dlpDialog.ask({ title: CP.sum.askT, body: CP.sum.askB, okLabel: CP.sum.askOk });
            if (ok) window.location.href = `/?simple=deploy&pack=${encodeURIComponent(st.pack)}`;
          });
        },
        nextStep: () => ({ text: CP.sum.next, tile: 'check' }) },
    ],
  };

  // 5. Why was something blocked? (the Path analyzer's answer)
  const CPa = COPY.path;
  function newToken() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
    let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
    return t;
  }
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  async function runPath(st, ui) {
    const scopes = [], channels = {};
    if (st.where.web) { scopes.push('zia_extras'); channels.ssl_inspection = 'zscaler'; channels.cloud_app_control = 'zscaler'; }
    if (st.where.data) { scopes.push('dlp'); channels.web_dlp = 'zscaler'; }
    if (st.where.app) scopes.push('zcc');
    const token = newToken();
    let job = null, stopped = false;
    const txt = $('smRunText');
    ui.onStop(async () => {
      stopped = true;
      try {
        if (job) await postJSON(`/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel`, {});
        else await postJSON('/api/dlp-packs/jobs/stop-before-start', { start_token: token });
      } catch (e) { /* the job ends anyway */ }
    });
    const body = Object.assign({ destination: st.site, network: 'off', platform: 'windows', scopes, channels, from_page: true, report_id: st.reportId || '' }, credBody());
    try {
      const start = await postJSON('/api/path-analyzer/start', body, { 'X-Start-Token': token });
      job = start.job_id;
      let since = 0;
      for (;;) {
        const snap = await getJSON(`/api/dlp-packs/jobs/${encodeURIComponent(job)}?since=${since}`);
        since = snap.next || since;
        if (txt) txt.textContent = plain(CPa.go.wait, { secs: Math.round(snap.elapsed_seconds || 0) });
        if (snap.status !== 'running') {
          if (snap.status === 'cancelled' || stopped || (snap.result && snap.result.status === 'stopped')) { ui.error(COPY.ui.stopped); return false; }
          if (snap.status !== 'done' || !snap.result) { ui.error(snap.error || COPY.ui.failed); return false; }
          st.out = snap.result; st.reportId = snap.result.report_id || '';
          return true;
        }
        await sleep(1200);
      }
    } catch (e) {
      ui.error(stopped ? COPY.ui.stopped : String((e && e.message) || e));
      return false;
    }
  }
  const ANSWER = { blocked: 'blocked', bypassed: 'bypassed', blind: 'blind', enforce: 'enforce', monitor: 'monitor', unknown: 'unknown',
    out_of_scope: 'outOfScope', conditional: 'conditional', metadata_only: 'metadataOnly' };
  const ANSWER_LIGHT = { blocked: 'look', bypassed: 'fix', blind: 'fix', enforce: 'good', monitor: 'look' };
  W.path = {
    steps: [
      { id: 'site', q: () => CPa.site.q,
        render: () => field('smSite', CPa.site.label, rich(CPa.site.hint), 'type="text" inputmode="url"'),
        after: st => setVal('smSite', st.site),
        check: st => { st.site = val('smSite'); return st.site ? '' : plain(COPY.ui.fillIn, { what: CPa.site.label }); } },
      { id: 'where', q: () => CPa.where.q,
        render: st => `<p>${rich(CPa.where.intro)}</p>` + choices('smWhere', CPa.where.q, ['web', 'data', 'app'].map(k => ({ value: k, title: CPa.where[k], sub: rich(CPa.where[k + 'Sub']) })), true, st.where || { web: true, data: true }),
        check: st => { st.where = pickedAll('smWhere'); return Object.values(st.where).some(Boolean) ? '' : COPY.ui.pickSome; } },
      Object.assign(connStep(), { id: 'pconn' }),
      { id: 'go', q: () => CPa.go.q, nextLabel: CPa.go.btn,
        render: () => `<p>${rich(CPa.go.time)}</p>${safeBox(COPY.ui.looksOnly)}<p id="smRunText" role="status" aria-live="polite"></p>`,
        next: (st, ui) => runPath(st, ui) },
      { id: 'answer', final: true, q: () => CPa.answer.q,
        render: st => {
          const out = st.out || {}; const v = out.verdict || {};
          const host = ((out.destination || {}).host) || st.site;
          const key = ANSWER[v.outcome] || 'none';
          const lines = [`<p class="sm-row">${light(ANSWER_LIGHT[v.outcome] || 'look')} <strong>${rich(CPa.answer[key], { host })}</strong></p>`];
          if (v.outcome === 'blocked' && v.blocked_by) lines.push(`<p>${rich(CPa.answer.blockedBy, { rule: `“${v.blocked_by}”` })}</p>`);
          if (v.outcome !== 'blocked') lines.push(`<p>${rich(CPa.answer.notBlocked)}</p>`);
          lines.push(`<p>${rich(CPa.answer.ifWrong, { host })}</p>`);
          lines.push(`<details class="sm-box"><summary>${E(CPa.answer.exact)}</summary><p>${E(v.headline || '')}</p><p class="sm-dim">${E(v.summary || '')}</p></details>`);
          return lines.join('');
        },
        nextStep: () => ({ text: CPa.answer.next, tile: 'check' }) },
    ],
  };

  // 6. Show what changed (the profile's history and this app's deployments)
  const CCh = COPY.changes;
  W.changes = {
    steps: [
      { id: 'what', q: () => CCh.what.q,
        render: st => choices('smWhat', CCh.what.q, [{ value: 'score', title: CCh.what.score, sub: rich(CCh.what.scoreSub) }, { value: 'added', title: CCh.what.added, sub: rich(CCh.what.addedSub) }], false, st.what || 'score'),
        check: st => { st.what = picked('smWhat'); return st.what ? '' : COPY.ui.pickOne; } },
      { id: 'show', final: true, q: () => CCh.show.q,
        load: async st => {
          st.err = '';
          try {
            if (st.what === 'added') {
              st.deps = (await getJSON('/api/deployments')).deployments || [];
              try { ((await getJSON('/api/dlp-packs')).packs || []).forEach(p => { PACK_NAMES[p.id] = p.name || p.id; }); } catch (e) { /* ids stay */ }
            }
            else if (S.conn && S.conn.kind === 'profile') st.prof = await getJSON(`/api/tenant-profiles/${encodeURIComponent(S.conn.id)}`);
          } catch (e) { st.err = String(e.message || e); }
        },
        render: st => (st.err ? errBox(st.err) : '') + (st.what === 'added' ? addedHtml(st.deps || []) : scoreHistoryHtml(st.prof)) + safeBox(COPY.ui.looksOnly),
        nextStep: () => ({ text: CCh.show.next, tile: 'check' }) },
    ],
  };
  const PACK_NAMES = {};
  const when = t => { try { return new Date(t).toLocaleString(); } catch (e) { return String(t || ''); } };
  function scoreHistoryHtml(prof) {
    const sh = CCh.show;
    if (!S.conn || S.conn.kind !== 'profile') return `<p class="sm-row">${light('look')} <span>${rich(sh.needSaved)}</span></p><p><button type="button" class="sm-btn primary" data-tile="connect">${E(COPY.tiles.connect.title)}</button></p>`;
    const h = ((prof && prof.history) || []).filter(x => x && x.score != null);
    if (!h.length) return `<p class="sm-row">${light('look')} <span>${rich(sh.none)}</span></p>`;
    const table = `<table class="sm-table"><caption class="sm-cap">${E(sh.histH)}</caption><thead><tr><th scope="col">${E(sh.colWhen)}</th><th scope="col">${E(sh.colScore)}</th><th scope="col">${E(sh.colFix)}</th></tr></thead><tbody>${
      h.slice(-5).reverse().map(x => `<tr><td>${E(when(x.at))}</td><td>${E(Math.round(x.score))}</td><td>${E(x.critical ?? '–')}</td></tr>`).join('')}</tbody></table>`;
    if (h.length < 2) return `<p class="sm-row">${light('look')} <span>${rich(sh.one)}</span></p>${table}`;
    const a = h[h.length - 2], b = h[h.length - 1];
    const sa = Math.round(a.score), sb = Math.round(b.score);
    const kind = sb > sa ? 'good' : sb < sa ? 'fix' : 'look';
    return `<p class="sm-row">${light(kind)} <strong>${rich(sh.moved, { a: sa, b: sb })}</strong></p>
      <p>${rich(sb > sa ? sh.up : sb < sa ? sh.down : sh.same)}</p>
      ${a.critical != null && b.critical != null ? `<p>${rich(sh.fails, { a: a.critical, b: b.critical })}</p>` : ''}
      ${table}`;
  }
  function addedHtml(deps) {
    const sh = CCh.show;
    if (!deps.length) return `<p class="sm-row">${light('good')} <span>${rich(sh.noDeploys)}</span></p>`;
    return `<ul class="sm-list">${deps.slice(0, 5).map(d => `<li><p>${rich(sh.deploy, { when: when(d.at), n: d.created || 0, packs: (d.packs || []).map(id => PACK_NAMES[id] || id).join(', ') || '–' })}</p>${
      d.created && d.remaining < d.created ? `<p class="sm-dim">${rich(sh.undone, { n: d.created - d.remaining })}</p>` : ''}</li>`).join('')}</ul>`;
  }

  // 7. Make a report for my boss (Word through /api/report/docx; a
  // spreadsheet through /api/report/findings-csv)
  const CR = COPY.report;
  W.report = {
    steps: [
      { id: 'need', q: () => COPY.tiles.report.title,
        render: () => (S.report
          ? `<p class="sm-row">${light('good')} <span>${rich(CR.sum.about, { org: (S.report.metadata || {}).org || connName(), score: S.report.score == null ? '–' : Math.round(S.report.score) })}</span></p>`
          : `<p class="sm-row">${light('look')} <span>${rich(COPY.ui.needCheck)}</span></p><p><button type="button" class="sm-btn primary" data-tile="check">${E(COPY.tiles.check.title)}</button></p>`),
        check: () => (S.report ? '' : COPY.ui.needCheck) },
      { id: 'kind', q: () => CR.kind.q,
        render: st => choices('smFile', CR.kind.q, [{ value: 'word', title: CR.kind.word, sub: rich(CR.kind.wordSub) }, { value: 'sheet', title: CR.kind.sheet, sub: rich(CR.kind.sheetSub) }], false, st.file || 'word'),
        check: st => { st.file = picked('smFile'); return st.file ? '' : COPY.ui.pickOne; } },
      { id: 'sum', final: true, q: () => CR.sum.q,
        render: () => `<p>${rich(CR.sum.share)}</p><p><button type="button" class="sm-btn primary" id="smMake">${E(CR.sum.btn)}</button></p><p id="smMade" role="status" aria-live="polite"></p>${safeBox(COPY.ui.looksOnly)}`,
        after: st => {
          const b = $('smMake'); if (!b) return;
          b.addEventListener('click', async () => {
            const out = $('smMade'); b.disabled = true; out.textContent = CR.sum.busy;
            try {
              const url = st.file === 'sheet' ? '/api/report/findings-csv' : '/api/report/docx';
              const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(S.report) });
              if (!r.ok) throw new Error(await reason(r));
              const blob = await r.blob();
              const org = String(((S.report || {}).metadata || {}).org || 'report').replace(/[^A-Za-z0-9_-]+/g, '_').slice(0, 60) || 'report';
              const a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = `zscaler_${org}_${new Date().toISOString().slice(0, 10)}${st.file === 'sheet' ? '_findings.csv' : '.docx'}`;
              document.body.appendChild(a); a.click(); a.remove();
              setTimeout(() => URL.revokeObjectURL(a.href), 4000);
              out.innerHTML = `${light('good')} ${rich(CR.sum.made)}`;
            } catch (e) {
              out.innerHTML = errBox(String((e && e.message) || e));
            } finally { b.disabled = false; }
          });
        },
        nextStep: () => ({ text: CR.sum.next, tile: 'fix' }) },
    ],
  };

  // ── The wizard runner ───────────────────────────────────────────
  const TILES = ['connect', 'check', 'fix', 'protect', 'path', 'changes', 'report'];
  let cur = null;   // { id, w, st, stepId, stop }
  function visible() { return cur.w.steps.filter(s => !s.skip || !s.skip(cur.st)); }
  function home(focus) {
    stopRunning();
    cur = null;
    $('smWizard').hidden = true; $('smWizard').innerHTML = '';
    $('smHome').hidden = false;
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    if (focus !== false) { const h = $('smHomeH'); h.setAttribute('tabindex', '-1'); h.focus(); }
  }
  function stopRunning() { if (cur && cur.stop) { try { cur.stop(); } catch (e) { /* ignore */ } } if (cur) cur.stop = null; }
  function open(id, focus) {
    if (!W[id]) return home(focus);
    stopRunning();
    cur = { id, w: W[id], st: {}, stepId: W[id].steps[0].id, stop: null };
    $('smHome').hidden = true; $('smWizard').hidden = false;
    if (location.hash !== '#' + id) history.pushState(null, '', '#' + id);
    show(focus !== false);
  }
  async function show(focus) {
    const steps = visible();
    let idx = steps.findIndex(s => s.id === cur.stepId);
    if (idx < 0) { idx = 0; cur.stepId = steps[0].id; }
    const step = steps[idx]; const total = steps.length; const id = cur.id; const here = cur;
    const wiz = $('smWizard');
    const pct = Math.round(((idx + 1) / total) * 100);
    const stepText = plain(COPY.ui.stepOf, { n: idx + 1, total });
    wiz.innerHTML = `<div class="sm-wiz-top"><p class="sm-wiz-title">${E(COPY.tiles[id].title)}</p><p class="sm-steptext" id="smStepText">${E(stepText)}</p></div>
      <div class="sm-progress" role="progressbar" aria-labelledby="smStepText" aria-valuemin="1" aria-valuemax="${total}" aria-valuenow="${idx + 1}" aria-valuetext="${E(stepText)}"><span style="width:${pct}%"></span></div>
      <h2 class="sm-h" id="smStepH" tabindex="-1">${E(step.q(cur.st))}</h2>
      <div class="sm-body" id="smStepBody"><p class="sm-dim">${E(COPY.ui.working)}</p></div>
      <div class="sm-err" id="smErr" role="alert"></div>
      <div class="sm-nav">
        <button type="button" class="sm-btn" id="smBack">← ${E(COPY.ui.back)}</button>
        <div class="sm-right">
          ${step.final ? `<button type="button" class="sm-btn primary" id="smDone">${E(COPY.ui.done)}</button>` : `<button type="button" class="sm-btn primary" id="smNext">${E(step.nextLabel || COPY.ui.next)} →</button>`}
        </div>
      </div>
      <p class="sm-foot"><a class="sm-expert" id="smExpertView" href="${E(EXPERT[id])}">${E(COPY.ui.expert)} →</a></p>`;
    $('smBack').addEventListener('click', back);
    if (step.final) $('smDone').addEventListener('click', () => home());
    else $('smNext').addEventListener('click', next);
    if (focus) $('smStepH').focus();
    say(`${stepText}. ${step.q(cur.st)}`);
    try { if (step.load) await step.load(cur.st); } catch (e) { if (cur === here) $('smStepBody').innerHTML = errBox(String((e && e.message) || e)); return; }
    if (cur !== here || cur.stepId !== step.id) return;   // moved on while loading
    const body = $('smStepBody');
    body.innerHTML = step.render(cur.st) + (step.final ? nextStepHtml(step) : '');
    if (step.after) step.after(cur.st);
    if (window.dlpIconize) { try { window.dlpIconize(body); } catch (e) { /* plain text stays */ } }
  }
  function nextStepHtml(step) {
    const ns = step.nextStep ? step.nextStep(cur.st) : null;
    if (!ns) return '';
    const key = EXPLAIN[cur.id]; const x = (window.DLP_EXPLAIN || {})[key];
    const action = ns.tile ? `<button type="button" class="sm-btn primary" data-tile="${E(ns.tile)}">${E(COPY.tiles[ns.tile].title)} →</button>`
      : ns.href ? `<a class="sm-btn primary" href="${E(ns.href)}">${E(ns.label || COPY.ui.expert)} →</a>` : '';
    return `<div class="sm-box nextstep"><h3>${E(COPY.ui.nextH)}</h3><p>${rich(ns.text)}</p>${action ? `<p>${action}</p>` : ''}
      ${x && x.next ? `<details><summary>${E(COPY.ui.expertTip)}</summary><p class="sm-dim">${E(x.next)}</p></details>` : ''}</div>`;
  }
  function setError(msg) { const el = $('smErr'); if (!el) return; el.innerHTML = msg ? `<p>${light('fix')} ${E(msg)}</p>` : ''; if (msg) say(msg); }
  async function next() {
    const steps = visible();
    const idx = steps.findIndex(s => s.id === cur.stepId);
    const step = steps[idx];
    setError('');
    const err = step.check ? step.check(cur.st) : '';
    if (err) { setError(err); return; }
    if (step.next) {
      const here = cur;
      const btn = $('smNext'); const backBtn = $('smBack');
      btn.disabled = true;
      // While a long task runs, Back becomes Stop.
      let stopFns = [];
      const ui = { onStop: fn => stopFns.push(fn), error: msg => { const el = $('smErr'); if (el) el.innerHTML = errBox(msg); say(msg); } };
      cur.stop = () => stopFns.forEach(fn => { try { fn(); } catch (e) { /* ignore */ } });
      backBtn.textContent = COPY.ui.stop;
      let ok = false;
      try { ok = await step.next(cur.st, ui); } catch (e) { ui.error(String((e && e.message) || e)); ok = false; }
      if (cur !== here) return;
      cur.stop = null;
      const b2 = $('smBack'); if (b2) b2.textContent = `← ${COPY.ui.back}`;
      const n2 = $('smNext'); if (n2) n2.disabled = false;
      if (!ok) return;
    }
    const after = visible();
    const at = after.findIndex(s => s.id === cur.stepId);
    if (at + 1 < after.length) { cur.stepId = after[at + 1].id; show(true); }
  }
  function back() {
    if (cur && cur.stop) { const s = cur.stop; cur.stop = null; s(); return; }
    const steps = visible();
    const idx = steps.findIndex(s => s.id === cur.stepId);
    if (idx <= 0) { home(); return; }
    cur.stepId = steps[idx - 1].id; show(true);
  }

  // ── Home ────────────────────────────────────────────────────────
  function renderHome() {
    $('smTiles').innerHTML = TILES.map(id => `<button type="button" class="sm-tile" data-tile="${id}">
      <span class="sm-ico" aria-hidden="true">${icon(ICONS[id])}</span><span class="sm-tt">${E(COPY.tiles[id].title)}</span>
      <span class="sm-tl">${E(COPY.tiles[id].line)}</span><span class="sm-tn">${E(CHANGES[id] ? COPY.ui.tagChange : COPY.ui.tagLook)}</span></button>`).join('');
    const list = $('smWordList');
    if (list) list.innerHTML = Object.keys(GLOSS).sort().map(k => `<dt>${E(GLOSS[k].term)}</dt><dd>${E(GLOSS[k].def)}</dd>`).join('');
  }

  // One click handler for tiles, chips and "open this task" buttons.
  document.addEventListener('click', e => {
    const t = e.target.closest && e.target.closest('.sm-term');
    if (t) {
      e.preventDefault();
      const d = $(t.getAttribute('aria-controls'));
      const open_ = t.getAttribute('aria-expanded') !== 'true';
      t.setAttribute('aria-expanded', String(open_));
      if (d) {
        // The definition opens under the sentence, not in the middle of it.
        const block = t.closest('p, li, .sm-hint, .sm-os, h3');
        if (open_ && block && d.parentElement !== block.parentElement) block.insertAdjacentElement('afterend', d);
        d.hidden = !open_;
      }
      return;
    }
    const tile = e.target.closest && e.target.closest('[data-tile]');
    if (tile) { e.preventDefault(); open(tile.getAttribute('data-tile')); }
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    const t = document.activeElement;
    if (t && t.classList && t.classList.contains('sm-term') && t.getAttribute('aria-expanded') === 'true') { t.click(); }
  });
  // Enter in a text field means Next.
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && cur && e.target && e.target.matches && e.target.matches('.sm-field input')) { e.preventDefault(); const n = $('smNext'); if (n && !n.disabled) n.click(); }
  });
  window.addEventListener('popstate', () => { const id = location.hash.slice(1); if (W[id]) { if (!cur || cur.id !== id) open(id); } else if (cur) home(); });

  // The choice of mode is remembered per browser.
  const expertLink = $('smExpertLink');
  if (expertLink) expertLink.addEventListener('click', () => writeRaw(LS_MODE, 'expert'));
  writeRaw(LS_MODE, 'simple');

  renderConn();
  renderHome();
  const first = location.hash.slice(1);
  if (W[first]) open(first, false);

  // For the tests: the copy and the wizards' shape (no secrets here).
  window.SIMPLE_MODE = { COPY, tiles: TILES, steps: id => (W[id] ? W[id].steps.map(s => s.id) : []) };
})();
