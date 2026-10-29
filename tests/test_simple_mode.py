"""Simple mode (/simple): the app as seven big tasks a newcomer can follow.

What is pinned here:
- readability: every sentence the page shows (simple.html, the COPY block of
  simple.js, the definitions in glossary.js) is measured with the
  Flesch-Kincaid grade level, using a simple syllable counter written below;
  the average must be at most grade 6 and no single sentence above grade 9;
- every jargon word is a tap-to-explain chip with a definition;
- every task is a wizard with progress ("Step 2 of 4"), Back, a summary, a
  next step and the expert view link;
- status is never colour alone; anything that changes the tenant is handed
  to the assessment page's own flow (write mode, preview, confirmation);
- the page follows the report-page conventions and is keyboard operable;
- the entry points on the assessment page, and the spreadsheet export.
"""
from __future__ import annotations

import io
import csv
import os
import re
import statistics

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


# ── Readability ─────────────────────────────────────────────────────────
# Product and screen names the reader has to see as they are spelled in
# Zscaler (a menu is called "Integration" whatever we would prefer). Each is
# counted as one short word, so it neither helps nor hurts a sentence.
PRODUCT_NAMES = [
    "Microsoft 365", "Google Drive", "Cloud App Control", "Client Connector", "ZIdentity", "Zscaler", "Gmail", "Excel",
    "Integration", "YES_I_UNDERSTAND", "acme.zslogin.net", ".zslogin.net", "drive.google.com", "dropbox.com",
]
MAX_AVERAGE_GRADE = 6.0
MAX_SENTENCE_GRADE = 9.0
# A label of one to three words ("Back", "Protect sensitive data") is not a
# sentence: the grade formula is meaningless on it. Labels still count in
# the average; the per-sentence ceiling applies from this many words on.
MIN_WORDS_FOR_CEILING = 4


def syllables(word: str) -> int:
    """A plain syllable counter: vowel groups, minus a silent final e."""
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 1   # a number or a symbol reads as one beat
    if len(w) <= 3:
        return 1
    w = re.sub(r"(?:[^laeiouy]es|[^laeiouy]ed|[^laeiouy]e)$", "", w)
    w = re.sub(r"^y", "", w)
    return max(1, len(re.findall(r"[aeiouy]{1,2}", w)))


def words(text: str):
    return re.findall(r"[A-Za-z0-9][A-Za-z0-9'’_-]*", text)


def grade(text: str) -> float:
    ws = words(text)
    if not ws:
        return 0.0
    syl = sum(syllables(w) for w in ws)
    return 0.39 * len(ws) + 11.8 * syl / len(ws) - 15.59


def _normalise(text: str) -> str:
    text = re.sub(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]", lambda m: m.group(2) or m.group(1), text)
    text = re.sub(r"\{\w+\}", "it", text)          # a value filled in at run time
    for name in sorted(PRODUCT_NAMES, key=len, reverse=True):
        text = text.replace(name, "Zed")
    return re.sub(r"[←→·–]", " ", text).strip()


def sentences(text: str):
    out = []
    for part in re.split(r"(?<=[.!?:])\s+", _normalise(text)):
        part = part.strip()
        if words(part):
            out.append(part)
    return out


def _js_strings(block: str):
    """Every single-quoted string in a block of JS, with the id of the
    innermost object literal it sits in (a screen's strings share one)."""
    out, stack, i, seq = [], [0], 0, 0
    while i < len(block):
        c = block[i]
        if c == "'":
            j, buf = i + 1, []
            while block[j] != "'":
                if block[j] == "\\":
                    buf.append(block[j + 1]); j += 2; continue
                buf.append(block[j]); j += 1
            out.append((stack[-1], "".join(buf)))
            i = j + 1
            continue
        if c == "/" and block[i:i + 2] == "//":
            i = block.index("\n", i)
            continue
        if c == "{":
            seq += 1; stack.append(seq)
        elif c == "}":
            stack.pop()
        i += 1
    return out


def copy_block():
    js = _read("simple.js")
    return js[js.index("// COPY-START"):js.index("// COPY-END")]


def copy_strings():
    return _js_strings(copy_block())


def glossary():
    js = _read("glossary.js")
    block = js[js.index("// GLOSSARY-START"):js.index("// GLOSSARY-END")]
    return {k.lower(): (t, d) for k, t, d in re.findall(r"'([^']+)': \{ term: '([^']+)', def: '([^']+)' \}", block)}


def html_texts():
    html = _read("simple.html")
    body = html[html.index("<body"):]
    body = re.sub(r"<script.*?</script>", " ", body, flags=re.S)
    attrs = re.findall(r'(?:aria-label|title|placeholder)="([^"]+)"', body)
    text = re.sub(r"<[^>]+>", "\n", body)
    lines = [re.sub(r"\s+", " ", t).strip() for t in text.split("\n")]
    return [t for t in lines if t] + attrs


def all_sentences():
    texts = [s for _, s in copy_strings()] + [d for _, d in glossary().values()] + html_texts()
    out = []
    for t in texts:
        out.extend(sentences(t))
    return out


def reading_levels():
    """(document grade, mean sentence grade, worst sentence, its grade, count)."""
    sents = all_sentences()
    ws = [w for s in sents for w in words(s)]
    doc = 0.39 * len(ws) / len(sents) + 11.8 * sum(syllables(w) for w in ws) / len(ws) - 15.59
    graded = [(grade(s), s) for s in sents]
    ceiling = [(g, s) for g, s in graded if len(words(s)) >= MIN_WORDS_FOR_CEILING]
    worst = max(ceiling)
    return doc, statistics.mean(g for g, _ in graded), worst[1], worst[0], len(sents)


def test_the_syllable_counter_and_the_formula_behave():
    assert [syllables(w) for w in ("cat", "table", "data", "computer", "information", "the", "safe")] == [1, 2, 2, 3, 4, 1, 1]
    assert grade("The cat sat on the mat.") < 0
    assert grade("Organisational information classification considerations.") > 20


def test_every_sentence_reads_at_grade_six_on_average_and_none_above_nine():
    doc, mean, worst, worst_grade, n = reading_levels()
    assert n > 150, "the extraction found the page's sentences"
    assert doc <= MAX_AVERAGE_GRADE, f"document grade {doc:.1f}"
    assert mean <= MAX_AVERAGE_GRADE, f"mean sentence grade {mean:.1f}"
    too_hard = [(round(grade(s), 1), s) for s in all_sentences() if len(words(s)) >= MIN_WORDS_FOR_CEILING and grade(s) > MAX_SENTENCE_GRADE]
    assert not too_hard, too_hard
    assert worst_grade <= MAX_SENTENCE_GRADE, (worst, worst_grade)


def test_no_sentence_outside_the_copy_block():
    """Every English sentence simple.js shows is in COPY (so it is measured):
    a string outside it may be a class, an id, a URL or a code word, not prose."""
    js = _read("simple.js")
    rest = js[:js.index("// COPY-START")] + js[js.index("// COPY-END"):]
    rest = re.sub(r"^\s*//.*$", "", rest, flags=re.M)
    prose = [s for _, s in _js_strings(rest) if re.match(r"[A-Z][a-z]+ [a-z]+ [a-z]+", s)]
    templ = [t for t in re.findall(r"`([^`]*)`", rest) if re.search(r">[A-Z][a-z]+ [a-z]+ [a-z]+ [a-z]+", t)]
    assert not prose and not templ, (prose, templ)


# ── Glossary chips ──────────────────────────────────────────────────────
JARGON = ["dlp", "ssl inspection", "pac file", "client connector", "tenant", "vanity domain", "client id", "client secret", "api client",
          "zidentity", "zia", "monitor-only", "write mode", "read-only", "policy pack", "dictionary", "preflight", "saas", "bypass",
          "encrypted", "url filtering", "cloud app control", "safety words", "spreadsheet", "scope", "channel", "endpoint", "engine", "deploy"]


def test_the_glossary_has_about_forty_short_definitions():
    g = glossary()
    assert len(g) >= 40
    for key, (term, definition) in g.items():
        assert key == key.lower() and term and 30 <= len(definition) <= 200, key
        assert 1 <= len(re.findall(r"[.!?](?:\s|$)", definition)) <= 3, key
    for must in ("dlp", "dictionary", "engine", "rule", "ssl inspection", "pac file", "client connector", "tenant", "policy pack",
                 "monitor-only", "write mode"):
        assert must in g, must


def test_every_chip_has_a_definition_and_every_jargon_word_is_explained_where_it_is_used():
    g = glossary()
    groups = {}
    for gid, s in copy_strings():
        groups.setdefault(gid, []).append(s)
    chips = re.findall(r"\[\[([^\]|]+)", copy_block() + _read("simple.html"))
    assert chips, "the page explains its words"
    missing = sorted({c.lower() for c in chips} - set(g))
    assert not missing, f"chips without a definition: {missing}"
    for gid, strings in groups.items():
        chipped = {c.lower() for s in strings for c in re.findall(r"\[\[([^\]|]+)", s)}
        for s in strings:
            bare = re.sub(r"\[\[[^\]]+\]\]", " ", s).lower()
            for term in JARGON:
                if re.search(rf"(?<![\w-]){re.escape(term)}", bare):
                    assert term in chipped, f"{term!r} is used without a chip on its screen: {s!r}"
    # The task tiles are buttons, which cannot hold a chip: no jargon there.
    tiles = re.search(r"tiles: \{(.*?)\n    \},", copy_block(), re.S).group(1).lower()
    assert not [t for t in JARGON if re.search(rf"(?<![\w-]){re.escape(t)}", tiles)]
    html = _read("simple.html")
    assert html.index("glossary.js") < html.index("simple.js")


def test_chips_are_real_buttons_that_open_and_close_with_the_keyboard():
    js = _read("simple.js")
    assert '<button type="button" class="sm-term" data-term="${E(k)}" aria-expanded="false" aria-controls="${id}">' in js
    assert 'role="note" hidden>${E(GLOSS[k].def)}</span>' in js
    assert "e.key !== 'Escape'" in js and "aria-expanded" in js
    # Every glossary word is also listed under "Words to know".
    assert "Object.keys(GLOSS).sort().map(k => `<dt>${E(GLOSS[k].term)}</dt><dd>${E(GLOSS[k].def)}</dd>`)" in js


# ── Wizards ─────────────────────────────────────────────────────────────
TILES = ["connect", "check", "fix", "protect", "path", "changes", "report"]


def test_every_tile_is_a_wizard_with_progress_back_next_a_summary_and_the_expert_view():
    js = _read("simple.js")
    assert f"const TILES = {TILES!r};".replace('"', "'") in js
    for t in TILES:
        assert f"  W.{t} = {{" in js, t
        block = js[js.index(f"  W.{t} = {{"):]
        block = block[: block.index("\n  };")]
        assert "final: true" in block and "nextStep:" in block, f"{t} ends with a summary and a next step"
        assert f"{t}: {{ title: '" in copy_block(), t
    assert "stepOf: 'Step {n} of {total}'" in js and "back: 'Back'" in js and "expert: 'Show me the expert view'" in js
    runner = js[js.index("async function show(focus)"):js.index("function nextStepHtml")]
    for needle in ('role="progressbar"', 'aria-valuenow="${idx + 1}"', 'id="smBack"', "COPY.ui.back", "COPY.ui.expert", "id=\"smStepH\" tabindex=\"-1\"",
                   "$('smStepH').focus()", "say(`${stepText}"):
        assert needle in runner, needle
    # Back on the first step goes to the task list; while a task runs, Back is Stop.
    assert "if (idx <= 0) { home(); return; }" in js and "backBtn.textContent = COPY.ui.stop;" in js
    # Every expert link exists for every task.
    for t in TILES:
        assert re.search(rf"\b{t}: '/", js[js.index("const EXPERT = {"):]), t


def test_the_next_step_comes_from_explain_js_and_the_findings():
    js = _read("simple.js")
    assert "const x = (window.DLP_EXPLAIN || {})[key];" in js and "x.next" in js
    ex = _read("explain.js")
    keys = set(re.findall(r"^\s{2}X\.(\w+) = \{", ex, re.M))
    mapped = re.search(r"const EXPLAIN = \{([^}]*)\}", js).group(1)
    for k in re.findall(r"'(\w+)'", mapped):
        assert k in keys, k
    assert "topFindings(rep, 1)[0]" in js and "nextFix" in js


def test_status_is_never_colour_alone():
    js = _read("simple.js")
    fn = js[js.index("function light(kind)"):js.index("function icon(name)")]
    assert '<span class="sm-dot" aria-hidden="true"></span>${E(COPY.lights[k])}' in fn
    assert "lights: { good: 'Good', look: 'Needs a look', fix: 'Fix this' }" in js
    # The colour classes appear only through light(); no other markup uses them.
    rest = js.replace(fn, "")
    assert not re.search(r"sm-light (good|look|fix)", rest)
    css = _read("simple.css")
    assert ".sm-light.good" in css and "var(--pass)" in css and "var(--fail)" in css


# ── Safety ──────────────────────────────────────────────────────────────
WRITE_ENDPOINTS = ["/api/dlp-packs/apply", "/api/write-mode", "/api/remediation/execute", "/api/remediation/plan", "/undo",
                   "/api/dlp-packs/removal/apply", "/api/proposals", "/api/migrate/", "/api/dlp-packs/upload", "/api/pack-library/upload",
                   "/from-tenant", "/import", "/verify"]


def test_simple_mode_never_writes_and_hands_changes_to_the_existing_flows():
    js = _read("simple.js")
    for ep in WRITE_ENDPOINTS:
        assert ep not in js, ep
    posts = re.findall(r"postJSON\('([^']+)'|postJSON\(`([^`]+)`|fetch\('([^']+)', \{ method: 'POST'|fetch\(url, \{ method: 'POST'", js)
    used = {p for t in posts for p in t if p}
    assert used <= {"/api/tenant/check", "/api/tenant-profiles", "/api/path-analyzer/start", "/api/dlp-packs/jobs/stop-before-start",
                    "/api/dlp-packs/jobs/${encodeURIComponent(job)}/cancel", "/api/assess",
                    "/api/offline/sample", "/api/offline/leave"}, used   # the sample tenant: offline, never a tenant write
    # Deploying goes through Deploy policy packs; fixing through Review & remediate.
    assert "window.location.href = `/?simple=deploy&pack=${encodeURIComponent(st.pack)}`" in js
    assert "`/?simple=fix&check=${encodeURIComponent(f.id)}`" in js
    entry = _read("simple_entry.js")
    assert "await openDlpPacksModal();" in entry and "openRemediationWizard(encodeURIComponent(check))" in entry
    assert "fetch(" not in entry, "the hand-off itself calls nothing: the page's own flows do"
    # The plain-words warning, with the existing write mode and its phrase.
    assert "warnH: 'This will change your Zscaler.'" in js
    assert "Nothing changes until you turn on [[write mode]] and type the [[safety words]]." in js
    assert "window.dlpDialog.ask({ title: CP.sum.askT" in js
    g = glossary()
    assert security.WRITE_CONFIRM_PHRASE in g["safety words"][1]
    studio = _read("deploy_studio.js")
    assert "dlg.phrase({ title: 'Enable write mode on this server?'" in studio, "the confirmation Simple mode relies on"
    # Read-only steps say so.
    assert js.count("safeBox(COPY.ui.looksOnly)") >= 5 and "looksOnly: 'This only looks. It changes nothing.'" in js
    assert "signInOnly: 'This only signs in. It reads nothing and changes nothing.'" in js


def test_reads_send_only_what_the_person_put_in_scope():
    js = _read("simple.js")
    run = js[js.index("async function runAssessment"):js.index("// 3. Fix the top problems")]
    assert "scopes: ['dlp'], channels" in run and "if (st.ch && st.ch[k]) channels[id] = 'zscaler';" in run
    path = js[js.index("async function runPath"):js.index("const ANSWER = {")]
    assert "from_page: true" in path and "if (st.where.app) scopes.push('zcc');" in path
    assert "ui.onStop(" in run and "ui.onStop(" in path and "stop-before-start" in path


def test_no_secret_is_stored_in_the_browser():
    js = _read("simple.js")
    for m in re.finditer(r"writeJSON\('(?:local|session)', (\w+), ([^)]+)\)", js):
        assert "secret" not in m.group(2).lower() and "sec" != m.group(2).strip(), m.group(0)
    conn = re.findall(r"setConn\(\{([^}]*)\}\)", js)
    assert conn and not [c for c in conn if re.search(r"(?<![\w])(secret|sec|client_secret)\s*:", c)]
    assert "secret: ''" in js and "S.secret = st.sec" in js


# ── Page conventions ────────────────────────────────────────────────────
def test_page_follows_the_report_page_conventions():
    html = _read("simple.html")
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', '<main class="rp-card', 'href="/"',
                   "Switch to expert mode", '<link rel="stylesheet" href="/app.css">', 'lang="en"', 'name="viewport"', 'class="skip-link"',
                   'role="status" aria-live="polite"'):
        assert needle in html, needle
    order = [html.index(f'<script src="/static/{s}"></script>') for s in
             ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js", "glossary.js", "simple.js")]
    assert order == sorted(order)
    css = _read("simple.css")
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", css), "theme tokens only"
    for banned in ("gradient", "backdrop-filter", "blur(", "box-shadow", "text-shadow"):
        assert banned not in css, banned
    assert "min-height: var(--ctl-lg)" in css and "prefers-reduced-motion" in css and "@media (max-width: 600px)" in css
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", _read("simple_entry.js"))


def test_route_cache_and_explain_entry():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.get("/simple")
    assert r.status_code == 200 and "Simple" in r.text and "no-cache" in r.headers.get("cache-control", "")
    ex = _read("explain.js")
    assert "  X.simple = {" in ex and "'/simple': 'simple'" in ex and "'simple'" in ex[ex.index("DLP_EXPLAIN_ORDER"):]
    assert ex.index("  X.help = {") < ex.index("  X.simple = {"), "placed right after the help entry"
    assert "key === 'simple'" in ex, "the expert explainer box is not shown in Simple mode"


def test_keyboard_operability():
    html, js = _read("simple.html"), _read("simple.js")
    # Only real controls are clickable: buttons, links, inputs, details.
    assert "onclick" not in html and "onclick" not in js
    assert not re.search(r'tabindex="[1-9]', html + js)
    assert not re.search(r"<(div|span|li)[^>]*data-tile", js), "a task opener is always a button"
    assert '<button type="button" class="sm-tile" data-tile="${id}">' in js
    # Labels on every field, focus moves to each new question, Enter means Next.
    assert '<label for="${id}">${E(label)}</label><input id="${id}"' in js and 'aria-describedby="${id}H"' in js
    assert "e.key === 'Enter' && cur" in js
    assert "<legend class=\"sr-only\">" in js and "<caption class=\"sm-cap\">" in js and '<th scope="col">' in js
    css = _read("simple.css")
    assert css.count(":focus-visible") >= 6


# ── The assessment page's entry points ──────────────────────────────────
def test_the_toolbar_opens_simple_mode_first_and_remembers_the_choice():
    html = _read("index.html")
    toolbar = html[html.index('<div class="hero-toolbar"'):]
    first = re.search(r'onclick="([^"]+)"', toolbar).group(1)
    assert first == "openSimpleMode()"
    fn = html[html.index("function openSimpleMode()"):html.index("function openPathAnalyzerTab()")]
    assert "localStorage.setItem('zsimple_mode', 'simple')" in fn and "try {" in fn and "window.location.href = '/simple'" in fn
    assert ("simple_entry.js", "script") in srv.GUI_ADDONS
    entry = _read("simple_entry.js")
    assert "New here? Try Simple mode" in entry and "if (!saved())" in entry and "save('expert')" in entry
    assert "try { return localStorage.getItem(KEY); } catch (e) { return null; }" in entry
    assert ".textContent = " in entry and "innerHTML" not in entry
    js = _read("simple.js")
    assert "writeRaw(LS_MODE, 'expert')" in js and "writeRaw(LS_MODE, 'simple')" in js


def test_the_home_page_is_unchanged_by_simple_mode():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    home = c.get("/").text
    assert "Made Easy" in home and "/static/simple_entry.js" in home and "/static/simple.js" not in home


# ── The spreadsheet ─────────────────────────────────────────────────────
def test_the_spreadsheet_lists_what_to_fix_first_in_plain_words_and_is_formula_safe():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    body = {"metadata": {"org": "Acme Health"}, "checks": [
        {"id": "1.1", "section": "DLP", "label": "Fine", "status": "PASS", "detail": "ok"},
        {"id": "2.1", "section": "SSL", "label": "=HYPERLINK(\"http://x\")", "status": "FAIL", "detail": "-bad",
         "plain": {"found": "SSL inspection is off.", "means": "DLP is blind.", "do": "Turn it on."}},
        {"id": "3.1", "section": "DLP", "label": "Look", "status": "REVIEW", "detail": ""},
    ]}
    r = c.post("/api/report/findings-csv", json=body)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert 'filename="zscaler_Acme_Health_' in r.headers["content-disposition"]
    text = r.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][:4] == ["Status", "Check", "Area", "Finding"]
    assert [x[0] for x in rows[1:]] == ["Fix this", "Needs a look", "Good"]
    assert rows[1][3].startswith("'=") and rows[1][7] == "'-bad" and rows[1][4] == "SSL inspection is off."
    assert c.post("/api/report/findings-csv", json={"checks": []}).status_code == 400
