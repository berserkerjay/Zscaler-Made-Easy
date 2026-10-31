/* Cloud Sandbox file hashes on Bulk changes (/report/operations, "Build new").
   One form on the shared engine (ops_zia_sandbox.py): paste the MD5 hashes of
   files your incident response confirmed as malicious, one per line with an
   optional comment, and they are added to the Cloud Sandbox custom block list.
   The form only builds the spec; the page does the rest: Read from the tenant,
   Preview, the gates (write mode, writer, assessor, the typed phrase), Apply,
   read-back and Undo. The server checks every hash again. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS || window.__opsZiaSandboxLoaded) return;
  window.__opsZiaSandboxLoaded = true;

  const MAX_CHARS = 20000;
  const MD5 = /^[0-9a-f]{32}$/;
  const F = { text: '' };

  // "hash comment words" or "hash,comment": the first token is the hash.
  function parse(text) {
    const out = [], bad = [];
    String(text || '').slice(0, MAX_CHARS).split(/\r?\n/).forEach((line, i) => {
      const t = line.trim();
      if (!t) return;
      const m = t.match(/^([^\s,;]+)[\s,;]*(.*)$/);
      const md5 = (m ? m[1] : t).toLowerCase();
      if (!MD5.test(md5)) bad.push(i + 1);
      out.push({ md5, comment: (m ? m[2] : '').slice(0, 100) });
    });
    return { out, bad };
  }

  function errorsHtml(E, res) {
    const errs = Object.entries((res && res.errors) || {});
    return errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : '';
  }

  function render(res, where, S, H) {
    const E = H.E;
    const max = res.max_hashes || 100;
    const counts = res.errors && res.errors.sandbox ? ''
      : `<div class="df-hint" id="zsbCounts">The list has ${E(res.blocked || 0)} blocked and ${E(res.allowed || 0)} allow-listed hash(es)${res.quota_left != null ? `; room for ${E(res.quota_left)} more` : ''}.</div>`;
    where.innerHTML = `${errorsHtml(E, res)}
      <p class="df-hint">Paste the MD5 hash of each file to block, one per line; anything after the hash on the line is kept as its comment. A blocked hash stops that file for every user as soon as the change is activated, without sandbox analysis, so check each one against the incident. Up to ${E(max)} per operation.</p>
      ${counts}
      <div class="op-block">
        <label class="lbl" for="zsbHashes">MD5 hashes to block</label>
        <textarea id="zsbHashes" rows="6" spellcheck="false" autocomplete="off" maxlength="${MAX_CHARS}" aria-describedby="zsbCheck" placeholder="44d88612fea8a8f36de82e1278abb02f IR-2026-031 dropper">${E(F.text)}</textarea>
        <div class="df-hint" id="zsbCheck" role="status" aria-live="polite"></div>
      </div>`;
    const ta = where.querySelector('#zsbHashes'), chk = where.querySelector('#zsbCheck');
    const show = () => {
      const p = parse(ta.value);
      chk.textContent = !p.out.length ? 'No hash yet.'
        : p.bad.length ? `Line${p.bad.length > 1 ? 's' : ''} ${p.bad.slice(0, 8).join(', ')}: not an MD5 hash (32 characters, 0-9 and a-f).`
          : `${p.out.length} hash(es) ready to preview.`;
    };
    ta.addEventListener('input', () => { F.text = ta.value; show(); });
    show();
  }

  function spec() {
    const p = parse(F.text);
    if (!p.out.length) throw new Error('Paste at least one MD5 hash.');
    if (p.bad.length) throw new Error(`Line ${p.bad[0]} is not an MD5 hash (32 characters, 0-9 and a-f).`);
    if (p.out.length > 100) throw new Error('At most 100 hashes per operation: split the list.');
    return { type: 'zia_sandbox_hashes', hashes: p.out };
  }

  window.OPS_PLUGINS.register({ type: 'zia_sandbox_hashes', render, spec });
})();
