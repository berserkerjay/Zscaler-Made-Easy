/* DLP dictionaries and engines on Bulk changes (/report/operations, "Change"),
   on the shared engine (ops_dlp_objects.py): create, edit or delete one
   custom dictionary or engine. Each engine shows its expression in words
   (the DLP explainer), and the preview says what a new or changed
   expression will mean, before and after. A dictionary or engine in use
   cannot be deleted. The page does the rest: Preview, the gates, Apply and
   Undo. Every tenant string is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.dlpo) S.dlpo = { obj: 'engine', act: 'update', pick: '', name: null, desc: null, expr: null, match: null, phrases: null, patterns: null, prox: null, conf: null };
    return S.dlpo;
  }
  function entriesText(list, key) {
    return (list || []).map(x => `${String(x.action || '').endsWith('UNIQUE') ? 'unique' : 'all'}: ${x[key]}`).join('\n');
  }
  function parseEntries(text, key) {
    return String(text || '').split('\n').map(l => l.trim()).filter(Boolean).map(l => {
      const m = /^(all|unique)\s*:\s*(.+)$/i.exec(l);
      return m ? { action: m[1].toLowerCase(), [key]: m[2] } : { action: 'all', [key]: l };
    });
  }
  function reset(z) { ['name', 'desc', 'expr', 'match', 'phrases', 'patterns', 'prox', 'conf'].forEach(k => { z[k] = null; }); }
  function render(res, where, S, H) {
    const E = H.E, z = st(S);
    const list = z.obj === 'dictionary' ? (res.dictionaries || []) : (res.engines || []);
    const cur = list.find(x => String(x.id) === z.pick) || null;
    const v = (k, f, d) => (z[k] != null ? z[k] : (cur && z.act === 'update' ? f(cur) : d));
    const errs = Object.entries(res.errors || {});
    const table = `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">${z.obj === 'dictionary' ? 'DLP dictionaries' : 'DLP engines'}</caption>
      <thead><tr><th scope="col">Pick</th><th scope="col">${z.obj === 'dictionary' ? 'Dictionary' : 'Engine'}</th><th scope="col">${z.obj === 'dictionary' ? 'Phrases and patterns' : 'What it detects'}</th><th scope="col">Used by</th></tr></thead>
      <tbody>${list.map(x => `<tr><td><input type="radio" name="dloPick" value="${E(x.id)}" aria-label="Pick ${E(x.name)}"${z.pick === String(x.id) ? ' checked' : ''}${!x.custom && !(z.obj === 'dictionary' && z.act === 'update' && x.confidence_threshold) ? ' disabled' : ''}></td>
        <td>${E(x.name)}<div class="df-by">${x.custom ? 'custom' : 'predefined'}${x.confidence_threshold ? ' · ' + E(x.confidence_threshold) : ''}</div></td>
        <td>${z.obj === 'dictionary' ? `${E((x.phrases || []).length)} phrase(s), ${E((x.patterns || []).length)} pattern(s)` : `${E(x.readable)}<div class="df-by">${E(x.summary)}</div><div class="df-by"><code>${E(x.expression)}</code></div>`}</td>
        <td>${z.obj === 'dictionary' ? (x.used_by || []).map(E).join('<br>') : (x.used_by || []).map(r => `${E(r.policy_label)} ${E(r.order)}: ${E(r.name)}`).join('<br>') || ''}${(x.used_by || []).length ? '' : '<span class="df-hint">nothing read here</span>'}</td></tr>`).join('') || '<tr><td colspan="4">None.</td></tr>'}</tbody></table></div>`;
    let form = '';
    if (z.act !== 'delete' && (z.act === 'create' || cur)) {
      const predefined = cur && !cur.custom;
      form = predefined ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Confidence</span><select id="dloConf" aria-label="Dictionary confidence">${(res.confidence_levels || []).map(c => `<option value="${E(c)}"${v('conf', x => x.confidence_threshold, '') === c ? ' selected' : ''}>${E(c)}</option>`).join('')}</select></label>
          <span class="df-hint">A predefined dictionary: only its confidence can be changed.</span></div>`
        : `<div class="op-row"><label class="df-ctl"><span class="lbl">Name</span><input id="dloName" value="${E(v('name', x => x.name, ''))}" maxlength="255" aria-label="Name"></label>
          <label class="df-ctl"><span class="lbl">Description</span><input id="dloDesc" value="${E(v('desc', x => x.description, ''))}" maxlength="255" aria-label="Description"></label></div>
        ${z.obj === 'engine' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Expression</span><textarea id="dloExpr" rows="3" maxlength="4000" spellcheck="false" aria-label="Engine expression">${E(v('expr', x => x.expression, ''))}</textarea></label></div>
          <div class="df-hint">Name dictionaries as D:&lt;name&gt; or D&lt;id&gt;.S, compare counts with &gt;, &gt;=, &lt;, &lt;= or =, join with AND, OR, NOT and parentheses: (D:Project names &gt; 2) AND (D:CREDIT_CARD &gt; 0). The preview says what it means in words.</div>`
          : `<div class="op-row"><label class="df-ctl"><span class="lbl">Match</span><select id="dloMatch" aria-label="Dictionary match type">${(res.match_types || []).map(m => `<option value="${E(m)}"${v('match', x => x.custom_phrase_match_type, 'MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY') === m ? ' selected' : ''}>${E(m)}</option>`).join('')}</select></label>
            <label class="df-ctl"><span class="lbl">Proximity (bytes)</span><input id="dloProx" type="number" min="0" max="10000" value="${E(v('prox', x => x.proximity || 0, 0))}" aria-label="Proximity in bytes"></label></div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Phrases</span><textarea id="dloPhrases" rows="4" maxlength="100000" spellcheck="false" aria-label="Phrases, one per line, optionally starting all: or unique:">${E(v('phrases', x => entriesText(x.phrases, 'phrase'), ''))}</textarea></label>
            <label class="df-ctl"><span class="lbl">Patterns</span><textarea id="dloPatterns" rows="4" maxlength="20000" spellcheck="false" aria-label="Patterns (regular expressions), one per line, optionally starting all: or unique:">${E(v('patterns', x => entriesText(x.patterns, 'pattern'), ''))}</textarea></label></div>
          <div class="df-hint">One per line; start a line with unique: to count each distinct match once (all: is the default). Patterns are checked against ZIA's limits and for runaway backtracking before anything is sent.</div>`}`;
    } else if (z.act === 'delete') {
      form = `<div class="df-hint">Something in use cannot be deleted. You type DELETE and its name to confirm; Undo creates it again (with a new id).</div>`;
    }
    where.innerHTML = `${errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, x]) => `<li>${E(k)}: ${E(x)}</li>`).join('')}</ul></div>` : ''}
      <div class="op-row"><fieldset class="op-inline"><legend>What</legend>
        <label><input type="radio" name="dloObj" value="engine"${z.obj === 'engine' ? ' checked' : ''}> An engine</label>
        <label><input type="radio" name="dloObj" value="dictionary"${z.obj === 'dictionary' ? ' checked' : ''}> A dictionary</label></fieldset>
        <fieldset class="op-inline"><legend>Do</legend>
        <label><input type="radio" name="dloAct" value="update"${z.act === 'update' ? ' checked' : ''}> Edit</label>
        <label><input type="radio" name="dloAct" value="create"${z.act === 'create' ? ' checked' : ''}> Create</label>
        <label><input type="radio" name="dloAct" value="delete"${z.act === 'delete' ? ' checked' : ''}> Delete</label></fieldset></div>
      ${z.act === 'create' ? '' : table}${form}`;
    const again = id => { render(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="dloObj"]').forEach(r => r.addEventListener('change', () => { z.obj = r.value; z.pick = ''; reset(z); again('dloObj'); }));
    where.querySelectorAll('input[name="dloAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; reset(z); again('dloAct'); }));
    where.querySelectorAll('input[name="dloPick"]').forEach(r => r.addEventListener('change', () => { z.pick = r.value; reset(z); again('dloPick'); }));
    [['dloName', 'name'], ['dloDesc', 'desc'], ['dloExpr', 'expr'], ['dloMatch', 'match'], ['dloProx', 'prox'], ['dloPhrases', 'phrases'], ['dloPatterns', 'patterns'], ['dloConf', 'conf']].forEach(([id, k]) => {
      const el = document.getElementById(id); if (el) el.addEventListener(el.tagName === 'SELECT' ? 'change' : 'input', () => { z[k] = el.value; });
    });
    S.dlpoRes = res;
  }
  function spec(S) {
    const z = st(S), res = S.dlpoRes || {};
    const list = z.obj === 'dictionary' ? (res.dictionaries || []) : (res.engines || []);
    const cur = list.find(x => String(x.id) === z.pick) || null;
    const base = { type: 'dlp_object_edit', object: z.obj, action: z.act };
    if (z.act !== 'create') {
      if (!cur) throw new Error('Pick one.');
      base.id = cur.id;
      if (z.act === 'delete') return base;
    }
    const f = {};
    if (cur && !cur.custom) {
      if (z.conf != null) f.confidence_threshold = z.conf;
    } else {
      if (z.name != null) f.name = z.name.trim();
      if (z.desc != null) f.description = z.desc.trim();
      if (z.obj === 'engine') { if (z.expr != null) f.expression = z.expr.trim(); }
      else {
        if (z.match != null) f.custom_phrase_match_type = z.match;
        if (z.prox != null) f.proximity = Number(z.prox) || 0;
        if (z.phrases != null) f.phrases = parseEntries(z.phrases, 'phrase');
        if (z.patterns != null) f.patterns = parseEntries(z.patterns, 'pattern');
      }
    }
    if (!Object.keys(f).length) throw new Error(z.act === 'create' ? 'Fill in the new one.' : 'Change at least one field.');
    base.fields = f;
    return base;
  }
  function plan(p, where, H) {
    const x = p.explain;
    if (!x) return;
    const E = H.E, card = document.createElement('div');
    card.className = 'bp-card info';
    const part = (label, e) => e ? `<div><strong>${E(label)}:</strong> ${E(e.summary || e.readable || '')}<div class="df-by">${E(e.readable || '')}</div>${e.error ? `<div class="df-by">${E(e.error)}</div>` : ''}</div>` : '';
    card.innerHTML = `<div class="t">What the expression means</div>${part('Now', x.before)}${part(x.before ? 'After the change' : 'It will detect', x.after)}`;
    where.prepend(card);
  }
  window.OPS_PLUGINS.register({ type: 'dlp_object_edit', render, spec, plan });
}());
