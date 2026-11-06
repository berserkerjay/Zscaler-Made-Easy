"""The * on new features (static/whats_new.js, with its styles in
static/hover_help.css and its help line in static/hover_help.js).

One manifest lists every new feature: the CHANGELOG.md release it came in,
a short label, what it is, and where it is marked. Only the features of the
newest two releases are marked, so when the next release goes into the
manifest the oldest set drops off.

Static half (no browser): the manifest is well formed, every date is a
CHANGELOG release and the two newest releases are in it, every mark names an
element that exists in its page's sources, every feature the two newest
CHANGELOG entries name has a mark (or a reason below why it has no home), the
engine writes no HTML and guards its storage, and every page loads it.

Browser half (node + headless Chrome over CDP, the harness of
tests/test_findings_reflow.py; skipped without either): the marks render on
each page, the * is hidden from screen readers and the name says "new"
(Chrome's own accessibility tree), the help on hover opens with "New in the
<date> update", nothing scrolls sideways at 320px, the * keeps the colour of
the words it follows in both themes with the glass on and off, an older
release is not marked, and "Hide new marks" in Advanced settings works and is
remembered. No tenant is read.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest

from test_c6_tooltips import PAGES, page_sources, selector_tokens, server_sources
from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
ENGINE = STATIC / "whats_new.js"
CHANGELOG = ROOT / "CHANGELOG.md"

# CHANGELOG phrases (bold or italic) in the two newest entries that have no
# home in the app's pages to mark. A new phrase must either be covered by a
# manifest feature's "changelog" list or be added here with its reason.
EXCLUDED = {
    # POV follow-ups (2026-11-04): made-up data in the sample tenant, no control of its own.
    "PRA credential pools and ZPA isolation profiles in the sample tenant": "sample tenant data read by backups and checks, not a control",
    # The agent workspace is for the agents that build the app, not a page or a control.
    "Layered context": "agent workspace files in the repository, not in the app",
    "Compiled references that can't drift": "agent workspace files in the repository, not in the app",
    # The entry's own structure, not features.
    "What you asked for": "the request, not a feature",
    "How": "how the change was built",
    "Findings": "the review's findings, fixed in place",
    "Highlights": "fixes to existing pages",
    "Fixes": "fixes to existing pages",
    "Verified": "the test results",
    # A release workflow builds it: a download, not a page or a control.
    "No-install edition": "built by the release workflow, outside the app",
    # On every control of every page: it has no single place to mark, and
    # every mark's own pop-up is this help.
    "Help on hover": "on every control; each mark's pop-up is it",
    # Team server (2026-10-31): a dialog shown only before an idle sign-out,
    # a server rule with no new control, and what is not built.
    "Still there?": "a dialog that appears only before an idle sign-out: no control to mark",
    "Not built in": "says what the change does not add",
    # The MCP server and the assistant skill (2026-10-31): tools and files an AI
    # assistant uses, outside the app's pages.
    "The MCP server answers live questions with the app's engines": "the MCP server's tools, used by an assistant, not a page",
    "Read-only, twice over; no write tool at all": "how the MCP tools are kept read-only, not a page",
    "Same sign-in and the Scope rule": "how the MCP server signs in and scopes its reads, not a page",
    "A skill for assistants": "files for an AI assistant (skills/), not a page",
    # A fix to existing routes (the profile's cloud), no new control.
    "Fix": "a fix to existing routes, nothing new to see",
    # Static analysis (SAST): test and CI tooling, no page or control.
    "bandit, offline, in every test run": "a test-run gate (tests/test_sast.py, make sast), not a page",
    "CodeQL in CI": "a GitHub Actions workflow, outside the app",
    "Every current finding triaged": "code fixes and reviewed suppressions, nothing to see",
    # SOC review (2026-11-04): the assistant's tools and a status word in the text.
    "Assistant tools": "the MCP server's tools, used by an assistant, not a page",
    "Unknown": "a status word on the page, not a control",
}


def _engine() -> str:
    return ENGINE.read_text(encoding="utf-8")


def load_manifest(text: str | None = None) -> dict:
    """The manifest as data: one JSON object assigned to window.WHATS_NEW at the top of whats_new.js."""
    text = _engine() if text is None else text
    m = re.search(r"window\.WHATS_NEW\s*=\s*(\{.*?\n\});\s*\n// ── end of the manifest", text, re.S)
    assert m, "whats_new.js must start with `window.WHATS_NEW = {...};` and the end-of-manifest line"
    return json.loads(m.group(1))


MAN = load_manifest()


def _marks():
    for f in MAN["features"]:
        for mk in f["marks"]:
            yield f, mk


def changelog_entries() -> list[tuple[str, str]]:
    """Every CHANGELOG entry as (date, text), newest first."""
    text = CHANGELOG.read_text(encoding="utf-8")
    parts = re.split(r"^## (\d{4}-\d{2}-\d{2})\s*$", text, flags=re.M)
    entries = list(zip(parts[1::2], parts[2::2]))
    assert len(entries) >= 2, "CHANGELOG.md has dated '## YYYY-MM-DD' entries"
    return entries


def marked_entries() -> list[tuple[str, str]]:
    """The newest `keep` CHANGELOG entries with something to mark: a release
    the manifest lists under "skipped" (nothing new to see) is passed over."""
    return [e for e in changelog_entries() if e[0] not in MAN.get("skipped", {})][:MAN["keep"]]


def changelog_phrases(body: str) -> set[str]:
    """The bold and italic phrases of an entry's bullets (the features it names)."""
    body = re.sub(r"`[^`\n]*`", "", body)   # code spans: a literal * is not a name
    found = set(re.findall(r"\*\*([^*\n]+?)\*\*", body))
    found |= set(re.findall(r"(?<![*\w])\*(?!\*)([^*\n]+?)(?<!\*)\*(?![*\w])", re.sub(r"\*\*[^*\n]+?\*\*", "", body)))
    return {p.strip().rstrip(".").strip() for p in found if p.strip()}


# ── Static tests ──────────────────────────────────────────────────────

def test_every_manifest_entry_is_complete_with_a_valid_date():
    """CWE-20 · ASVS V5.1.3 · WCAG 2.2 SC 3.3.2: every feature has a unique id, a real date, a label, what it is and at least one mark."""
    ids, bad = set(), []
    for f in MAN["features"]:
        try:
            date.fromisoformat(f.get("release", ""))
        except (TypeError, ValueError):
            bad.append((f.get("id"), "release is not a YYYY-MM-DD date"))
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,60}", f.get("id", "")) or f["id"] in ids:
            bad.append((f.get("id"), "id missing, malformed or repeated"))
        ids.add(f.get("id"))
        for k in ("label", "what"):
            if not str(f.get(k, "")).strip():
                bad.append((f.get("id"), f"no {k}"))
        if not f.get("changelog") or not f.get("marks"):
            bad.append((f.get("id"), "no changelog phrase or no mark"))
        if set(f) - {"id", "release", "label", "what", "changelog", "marks"}:
            bad.append((f.get("id"), "unknown key"))
        for mk in f.get("marks", []):
            if mk.get("page") not in PAGES or not str(mk.get("at", "")).strip() or set(mk) - {"page", "at", "control", "shown"}:
                bad.append((f.get("id"), mk))
    assert not bad, bad
    for d in list(MAN["releases"]) + list(MAN.get("skipped", {})):
        date.fromisoformat(d)
    assert all(str(why).strip() for why in MAN.get("skipped", {}).values()), "a skipped release says why"
    assert not set(MAN["releases"]) & set(MAN.get("skipped", {}))
    assert MAN["keep"] == 2


def test_the_manifest_words_are_plain_text():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: labels and words carry no markup (they are set as text anyway)."""
    bad = [(f["id"], k) for f in MAN["features"] for k in ("label", "what") if re.search(r"[<>]", f[k])]
    assert not bad, bad


def test_every_release_date_is_a_changelog_release_and_the_newest_two_are_listed():
    """SSDF PW.1.2 · ASVS V1.14.1: each date is a CHANGELOG.md release; every release newer than the marked ones is listed as skipped, with a reason."""
    dates = [d for d, _ in changelog_entries()]
    stray = sorted(({f["release"] for f in MAN["features"]} | set(MAN["releases"]) | set(MAN.get("skipped", {}))) - set(dates))
    assert not stray, f"not a CHANGELOG.md release: {stray}"
    marked = [d for d, _ in marked_entries()]
    assert sorted(MAN["releases"], reverse=True) == marked, f"whats_new.js must list {marked} under releases"
    newer = [d for d in dates if d > marked[-1] and d not in marked]
    assert set(newer) <= set(MAN.get("skipped", {})), f"add {newer} to whats_new.js: its features under releases, or under skipped with why"


@pytest.mark.parametrize("fid,page,sel", [(f["id"], mk["page"], s) for f, mk in _marks() for s in filter(None, (mk["at"], mk.get("control")))])
def test_every_mark_target_exists_on_its_page(fid, page, sel):
    """WCAG 2.2 SC 1.3.1 · CWE-1164: every id, class and attribute a mark's selector uses is in that page's sources (no orphan marks)."""
    src = page_sources(page)
    missing = []
    for kind, tok in selector_tokens(sel):
        pieces = [w for w in re.split(r"[^A-Za-z0-9]+", tok) if len(w) > 1]
        built = kind in ("value", "id") and pieces and re.search(r"[^A-Za-z0-9]", tok) and all(w in src or w in server_sources() for w in pieces)
        if tok not in src and not built:
            missing.append(f"{kind} {tok!r}")
    assert not missing, f"{fid} on {page}: {sel} -> {missing}"


def test_every_marked_page_has_a_legend_place():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2: each page with a mark has the element the "* New in this version" legend goes in."""
    legend = MAN["legend"]
    bad = []
    for page in sorted({mk["page"] for _, mk in _marks()}):
        anchors = legend.get(page) or legend["*"]
        src = page_sources(page)
        if not any(tok in src for a in anchors for _, tok in selector_tokens(a)):
            bad.append((page, anchors))
    assert not bad, bad


def test_every_new_changelog_feature_with_a_ui_home_is_marked():
    """SSDF PW.1.2 · WCAG 2.2 SC 3.2.4: each feature the two newest CHANGELOG releases with something to mark name is in the manifest, or excluded above with a reason."""
    covered = {p for f in MAN["features"] for p in f["changelog"]}
    missing, phrases = [], set()
    for d, body in marked_entries():
        for phrase in sorted(changelog_phrases(body)):
            phrases.add(phrase)
            if phrase not in covered and phrase not in EXCLUDED:
                missing.append(f"{d}: {phrase}")
    assert not missing, "map these in static/whats_new.js or explain them in EXCLUDED: " + "; ".join(missing)
    unknown = sorted(covered - phrases)
    assert not unknown, f"manifest names CHANGELOG phrases that are not in the two newest entries: {unknown}"
    # Each marked release has something marked (a count over both releases
    # depended on how many features one release happened to bring).
    assert all(covered & changelog_phrases(body) for _, body in marked_entries()), "a marked release with nothing marked"


def test_the_phrase_parser_reads_bold_and_italic_names():
    """CWE-20: the CHANGELOG reader finds bold and italic names and ignores the ** of bold ones (the coverage check relies on it)."""
    got = changelog_phrases("- **Liquid Glass.** see *Test a list*, `a*b`, a `*` and **Quality score** (x)")
    assert got == {"Liquid Glass", "Test a list", "Quality score"}


def test_the_engine_never_writes_html():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: marks, hidden words and the legend are built with textContent only."""
    js = re.sub(r"//[^\n]*|/\*.*?\*/", "", _engine(), flags=re.S)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute('on"):
        assert sink not in js, sink
    assert "textContent" in js


def test_the_hide_choice_storage_is_guarded():
    """ASVS V7.4.1 · CWE-755: every localStorage call sits in a try block (storage may throw); marks show by default."""
    lines = _engine().splitlines()
    calls = [i for i, line in enumerate(lines) if re.search(r"\blocalStorage\.(getItem|setItem|removeItem)\(", line)]
    assert calls
    for i in calls:
        assert "try" in lines[i] or "try" in "\n".join(lines[max(0, i - 3):i]), lines[i]
    assert "catch (e) { return false; }" in _engine(), "blocked storage means the marks show"


def test_every_page_loads_the_marks():
    """ASVS V14.4 · WCAG 2.2 SC 3.2.3: the home page gets whats_new.js through GUI_ADDONS (before the hover help) and every other page through report_theme.js."""
    import dlp_api_server as srv
    names = [n for n, _ in srv.GUI_ADDONS]
    assert ("whats_new.js", "script") in srv.GUI_ADDONS and names.index("whats_new.js") < names.index("hover_help.js")
    theme = (STATIC / "report_theme.js").read_text(encoding="utf-8")
    assert "s.src = '/static/whats_new.js';" in theme
    for page, name in PAGES.items():
        if page != "/":
            assert '<script src="/static/report_theme.js"></script>' in (STATIC / name).read_text(encoding="utf-8"), page


def test_the_star_is_a_superscript_button_in_the_accent_colour():
    """WCAG 2.2 SC 1.4.3 · SC 2.5.8 · SC 2.4.7: the * is drawn by CSS in the accent text token (4.5:1 on the page, card and well in both themes), on a 24px target with a visible focus ring; the legend's * matches."""
    css = (STATIC / "hover_help.css").read_text(encoding="utf-8")
    assert re.search(r"\.hh-mark\.hh-mark-new \{[^}]*color: var\(--accent", css)
    assert re.search(r'\.hh-mark\.hh-mark-new::before \{ content: "\*"; \}', css)
    assert re.search(r"\.hh-mark, [^{]*\{[^}]*width: 24px !important; height: 24px !important", css), "SC 2.5.8: 24px target"
    assert ".hh-mark:focus-visible" in css, "SC 2.4.7: a visible focus ring"
    assert re.search(r"\.wn-legend \.wn-legend-mark \{[^}]*color: var\(--accent", css)


def test_the_star_comes_from_the_item_and_is_its_own_trigger():
    """WCAG 2.2 SC 1.4.13 · SC 4.1.2: whats_new.js only puts the words on the item (data-wn-new); the help marks draw the * as its own button named "New in this version: <item>", re-read when the words change."""
    js = (STATIC / "hover_help.js").read_text(encoding="utf-8")
    assert "getAttribute('data-wn-new')" in js and "'New in this version: ' + name" in js and "makeMark('new')" in js
    assert "'data-wn-new']" in js, "the observer re-reads an item when its words change"
    wn = re.sub(r"//[^\n]*", "", _engine())
    assert "setAttribute('data-wn-new', text)" in wn
    assert "aria-label" not in wn, "whats_new.js never renames a control"


def _node():
    node = shutil.which("node")
    if not node:
        pytest.skip("needs node")
    return node


def _run_engine(script: str):
    stub = ("global.window = {}; global.document = { body: null, documentElement: { getAttribute() { return null; } }, addEventListener() {} };"
            f"require({json.dumps(str(ENGINE))}); const W = window.WhatsNew;")
    r = subprocess.run([_node(), "-e", stub + script], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_only_the_newest_two_releases_are_marked():
    """WCAG 2.2 SC 3.2.4 · CWE-1164: the marks follow the newest two releases; an older release is not marked, and a newer one pushes the oldest set out."""
    out = _run_engine(r"""
const f = (id, release) => ({ id, release, label: id, what: id, changelog: [id], marks: [{ page: '/', at: '#x' }] });
const m = { keep: 2, releases: { '2026-10-29': 'a', '2026-10-28': 'b' }, features: [f('old', '2026-10-26'), f('b', '2026-10-28'), f('a', '2026-10-29')] };
const now = W.active(m).map(x => x.id).sort();
m.releases['2026-10-30'] = 'next';
const next = W.active(m).map(x => x.id).sort();
const bad = W.active({ keep: 2, features: [f('nodate', ''), f('junk', '29/10/2026'), f('ok', '2026-10-29')] }).map(x => x.id);
console.log(JSON.stringify({ now, next, bad, real: W.releases(), words: W.words([f('p', '2026-10-28'), f('q', '2026-10-29'), f('r', '2026-10-28')]) }));
""")
    assert out["now"] == ["a", "b"], "2026-10-26 is older than the newest two releases"
    assert out["next"] == ["a"], "a release on 2026-10-30 drops the 2026-10-28 set"
    assert out["bad"] == ["ok"], "a feature without a valid date is never marked"
    assert out["real"] == [d for d, _ in marked_entries()]
    assert out["words"] == "New in the 2026-10-29 update: q New in the 2026-10-28 update: p r"


# ── In a real browser ─────────────────────────────────────────────────
#
# Release-agnostic: which items the tour points at, what their pop-ups must
# say and how the next release rotates the marks are all derived from the
# manifest, so a new release (or a feature added to one) never needs this
# file rewritten.

# Pages toured, and the marks there that show without a tenant (the rest
# appear after a read or in a dialog: "shown" in the manifest).
BROWSER_PAGES = ["/", "/report/path", "/report/pov", "/report/advanced", "/report/operations", "/report/fleet",
                 "/report/motion", "/report/live", "/simple"]
NARROW = ["/", "/report/path", "/report/pov", "/report/advanced", "/report/operations", "/simple"]


def _load_marks():
    """{page: [{at, releases}]}: one record per marked item (two features can share one)."""
    out = {}
    for f, mk in _marks():
        if mk["page"] in BROWSER_PAGES and not mk.get("shown"):
            recs = out.setdefault(mk["page"], [])
            rec = next((r for r in recs if r["at"] == mk["at"]), None)
            if rec is None:
                recs.append({"at": mk["at"], "releases": [f["release"]]})
            elif f["release"] not in rec["releases"]:
                rec["releases"].append(f["release"])
    return out


def marked_releases() -> list[str]:
    """The releases the marks follow, newest first (the engine's own rule)."""
    return [d for d, _ in marked_entries()]


def expected_words(page: str, at: str) -> str:
    """What whats_new.js puts on an item: "New in the <date> update: <what>
    ...", one part per release, newest first (WhatsNew.words)."""
    by: dict[str, list[str]] = {}
    for f, mk in _marks():
        if mk["page"] == page and mk["at"] == at and f["release"] in marked_releases():
            by.setdefault(f["release"], []).append(re.sub(r"\s+", " ", f["what"]).strip())
    return " ".join(f"New in the {d} update: {' '.join(w)}" for d, w in sorted(by.items(), reverse=True))


def _probes() -> dict:
    """The items the hover, keyboard and rotation checks use, from the
    manifest: on one toured page, items marked only by the newest release
    and items marked only by the one before it (by a plain #id), so the
    browser can take the first of each that is on screen. The rotation adds
    a release older than every marked one and one the day after the newest.
    The Hide new marks check counts on the toured page with the most marks."""
    rel = marked_releases()
    newest, older = rel[0], rel[1]
    marks = _load_marks()
    plain = re.compile(r"#[A-Za-z][\w-]*")
    pick = None
    for page in ["/report/path"] + [p for p in BROWSER_PAGES if p != "/report/path"]:
        new = [m["at"] for m in marks.get(page, []) if m["releases"] == [newest] and plain.fullmatch(m["at"])]
        old = [m["at"] for m in marks.get(page, []) if m["releases"] == [older] and plain.fullmatch(m["at"])]
        if new and old:
            pick = {"page": page, "new": new, "old": old}
            break
    counted = sorted((p for p in marks if p != "/"), key=lambda p: (-len(marks[p]), BROWSER_PAGES.index(p)))
    return {"newest": newest, "older": older, "pick": pick, "hidePage": counted[0] if counted else "/report/advanced",
            "past": (date.fromisoformat(rel[-1]) - timedelta(days=400)).isoformat(),
            "next": (date.fromisoformat(newest) + timedelta(days=1)).isoformat()}


PROBES = _probes()


def test_the_manifest_gives_the_tour_items_to_point_at():
    """WCAG 2.2 SC 3.2.4 · CWE-1164: the newest release and the one before it each mark at least one item, by #id, on one toured page."""
    assert PROBES["pick"], (f"no toured page has an item marked only by {PROBES['newest']} and one marked only by {PROBES['older']} "
                            "(by a plain #id): mark one of each in static/whats_new.js")


DRIVER = CDP_PRELUDE + EVENTS + r"""
const [marksJson, narrowJson, probesJson] = args;
const MARKS = JSON.parse(marksJson), PR = JSON.parse(probesJson);
const out = { pages: {}, narrow: {}, themes: {}, both: [], headings: [] };
await send('DOM.enable'); await send('Accessibility.enable');
await go('/');
await ev(`(localStorage.setItem('zsimple_mode', 'expert'), localStorage.removeItem('zme_hide_new_marks'), true)`);
const frame = () => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
const open = async url => { await go(url); await settle(url, 5000); await until(() => ev(`!!window.WhatsNew && !!window.HoverHelp`), url + ' marks loaded'); await ev(`(window.HoverHelp.scan(), 1)`); await frame(); };
// Chrome's accessible name for the element the selector finds.
const axName = async sel => {
  const root = (await send('DOM.getDocument', { depth: 0 })).result.root.nodeId;
  const q = await send('DOM.querySelector', { nodeId: root, selector: sel });
  if (!q.result || !q.result.nodeId) return null;
  const t = await send('Accessibility.getPartialAXTree', { nodeId: q.result.nodeId, fetchRelatives: false });
  const n = ((t.result || {}).nodes || [])[0];
  return n && n.name ? String(n.name.value) : '';
};
// The * mark of an item.
const STAR = sel => `window.HoverHelp.marks().find(m => m.__hhFor === document.querySelector(${JSON.stringify(sel)}) && m.getAttribute('data-hh-mark') === 'new')`;
const PROBE = `((m, i) => {
  const host = document.querySelector(m.at); if (!host) return { at: m.at, host: false };
  const star = window.HoverHelp.marks().find(k => k.__hhFor === host && k.getAttribute('data-hh-mark') === 'new');
  if (star) star.setAttribute('data-wn-probe', String(i));
  const r = star ? star.getBoundingClientRect() : null, h = host.getBoundingClientRect();
  return { at: m.at, releases: m.releases, host: true, star: !!star, tag: star ? star.tagName : '', glyph: star ? getComputedStyle(star, '::before').content : '',
    words: host.textContent, news: host.getAttribute('data-wn-new') || '', expanded: star ? star.getAttribute('aria-expanded') : '',
    desc: star ? (document.getElementById(star.getAttribute('aria-describedby') || '') || {}).textContent || '' : '',
    heading: /^H[1-6]$/.test(host.tagName),
    beside: !!(star && host.getClientRects().length && r.width >= 24 && r.height >= 24 && Math.abs((r.top + r.bottom) / 2 - (h.top + h.bottom) / 2) <= Math.max(h.height, 24)) };
})`;
// Items with both a * and a ? (in the order the marks come), on this page.
const BOTH = `(() => { const by = new Map(); window.HoverHelp.marks().forEach(m => { const l = by.get(m.__hhFor) || []; l.push(m); by.set(m.__hhFor, l); });
  return [...by.entries()].filter(([el, ms]) => el && el.isConnected && ms.some(m => m.getAttribute('data-hh-mark') === 'new') && ms.some(m => m.getAttribute('data-hh-mark') === 'help'))
    .slice(0, 3).map(([el, ms]) => ms.map(m => m.getAttribute('data-hh-mark') + ':' + (m.getAttribute('aria-label') || ''))); })()`;
for (const [page, marks] of Object.entries(MARKS)) {
  await open(page);
  const rec = await ev(`${JSON.stringify(marks)}.map(${PROBE})`);
  for (let i = 0; i < rec.length; i++) {
    rec[i].name = await axName(`[data-wn-probe="${i}"]`);
    if (rec[i].heading) out.headings.push({ page, at: rec[i].at, name: await axName(rec[i].at) });
  }
  for (const b of await ev(BOTH)) out.both.push({ page, marks: b });
  out.pages[page] = { marks: rec, legend: await ev(`(() => { const l = document.querySelector('.wn-legend'); return l ? { text: l.textContent, star: l.querySelector('[aria-hidden="true"]') ? l.querySelector('[aria-hidden="true"]').textContent : '' } : null; })()`),
                      errors: seen.errors.splice(0) };
  trace('page', page);
}

// Once the marks are placed the page goes quiet: placing them never asks for
// another pass (on a page with an item that has both a * and a ?; Advanced
// settings when it has one). Only changes to the marks count: a page's own
// live content (a running flow, a status line) is not the marks' doing.
const quietPage = out.both.some(b => b.page === '/report/advanced') ? '/report/advanced' : (out.both.length ? out.both[0].page : '/report/advanced');
// The page's own reads, in flight (a busy computer answers them late, and
// content they reveal shows its marks then: that is not a rescan loop).
const inflight = new Set();
const _onmsgNet = ws.onmessage;
ws.onmessage = e => { _onmsgNet(e); const m = JSON.parse(e.data);
  if (m.method === 'Network.requestWillBeSent' && m.params.request.url.startsWith(base)) inflight.add(m.params.requestId);
  if (m.method === 'Network.loadingFinished' || m.method === 'Network.loadingFailed') inflight.delete(m.params.requestId); };
await open(quietPage);
// The page's own late content (a status box filled after its fetch) lands
// first: wait until none of its reads is in flight, then for 600 ms without
// any change (at most 8 s), and again if that change started another read.
for (let i = 0; i < 3; i++) {
  await until(async () => inflight.size === 0, quietPage + ' reads answered', 15000).catch(() => null);   // a stream never ends: measure anyway
  await ev(`new Promise(r => { let t = null; const done = () => { mo.disconnect(); clearTimeout(cap); r(true); };
    const mo = new MutationObserver(() => { clearTimeout(t); t = setTimeout(done, 600); });
    mo.observe(document.body, { subtree: true, childList: true, attributes: true }); t = setTimeout(done, 600); const cap = setTimeout(done, 8000); })`);
  if (inflight.size === 0) break;
}
out.quiet = await ev(`new Promise(r => { let n = 0;
  const MARK = /(^|\\s)(hh-mark|hh-mark-new|wn-legend|wn-legend-mark)(\\s|$)/;
  const isMark = x => x && x.nodeType === 1 && (MARK.test(x.className || '') || !!(x.querySelector && x.querySelector('.hh-mark, .wn-legend')));
  const ATTRS = ['data-wn-new', 'data-wn-for', 'data-hh-mark', 'aria-describedby', 'aria-expanded'];
  const mo = new MutationObserver(ms => { ms.forEach(m => {
    if (m.type === 'attributes' ? (ATTRS.includes(m.attributeName) || isMark(m.target)) : ([...m.addedNodes].some(isMark) || [...m.removedNodes].some(isMark))) n++; }); });
  mo.observe(document.body, { subtree: true, childList: true, attributes: true });
  // The page's own late change (a status line filled after a slow read)
  // asks the marks to rescan: a rescan of settled marks changes nothing.
  const own = document.createElement('p'); own.textContent = 'status'; document.body.appendChild(own);
  setTimeout(() => { own.textContent = 'status, later'; own.className = 'later'; }, 300);
  setTimeout(() => { mo.disconnect(); own.remove(); r(n); }, 1500); })`);
out.quietPage = quietPage;

if (PR.pick) {
  // The first item of each release that is on screen with its *.
  await open(PR.pick.page);
  const onScreen = async list => { for (const at of list) if (await ev(`(() => { const e = document.querySelector(${JSON.stringify(at)}); return !!e && e.getClientRects().length > 0 && !!(${STAR(at)}); })()`)) return at; return null; };
  const NEW = await onScreen(PR.pick.new), OLD = await onScreen(PR.pick.old);
  out.picked = { page: PR.pick.page, new: NEW, old: OLD };
  if (NEW && OLD) {
    // The * is its own trigger: pointing at it opens "New in the <date> update"; pointing at the item opens nothing.
    const hoverAt = async js => {
      const r = await ev(`(() => { const e = ${js}; e.scrollIntoView({ block: 'center', behavior: 'instant' }); const b = e.getBoundingClientRect(); return { x: b.left + b.width / 2, y: b.top + b.height / 2 }; })()`);
      await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 2, y: 890, button: 'none' });
      await ev(`(window.HoverHelp.hide(), true)`);
      await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: r.x, y: r.y, button: 'none' });
      await until(() => ev(`(() => { const t = document.getElementById('hhTip'); return !!t && !t.hidden; })()`), 'the help', 2000).catch(() => null);
      return ev(`(() => { const t = document.getElementById('hhTip'); if (!t || t.hidden) return null; const first = t.querySelector('p'); return { first: first.className, text: first.textContent, all: t.textContent }; })()`);
    };
    out.hover = { item: await hoverAt(`document.querySelector(${JSON.stringify(NEW)})`), newest: await hoverAt(STAR(NEW)), older: await hoverAt(STAR(OLD)) };
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 2, y: 890, button: 'none' });
    await ev(`(window.HoverHelp.hide(), true)`);
    // Keyboard: focus alone opens nothing; Enter opens it.
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Shift', code: 'ShiftLeft', windowsVirtualKeyCode: 16 });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Shift', code: 'ShiftLeft', windowsVirtualKeyCode: 16 });
    await ev(`(${STAR(OLD)}.focus(), true)`);
    await frame();
    const focusOnly = await ev(`!document.getElementById('hhTip').hidden`);
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
    await frame();
    out.focus = await ev(`(() => { const t = document.getElementById('hhTip'); const b = document.activeElement; const s = getComputedStyle(b); return { focusOnly: ${focusOnly}, open: !!t && !t.hidden, text: t ? t.textContent : '', ring: s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0, w: b.getBoundingClientRect().width, h: b.getBoundingClientRect().height, expanded: b.getAttribute('aria-expanded') }; })()`);
    await ev(`(window.HoverHelp.hide(), true)`);

    // An older release is not marked; the next release pushes the oldest set out.
    out.rotate = await ev(`(() => {
      const W = window.WhatsNew, H = window.HoverHelp, NEW = ${JSON.stringify(NEW)}, OLD = ${JSON.stringify(OLD)};
      const probe = document.createElement('span'); probe.id = 'wnProbe'; probe.textContent = 'Probe';
      (document.querySelector('main') || document.body).appendChild(probe);
      const has = sel => { const e = document.querySelector(sel); H.scan(); return !!e && (e.hasAttribute('data-wn-new') || H.marks().some(m => m.__hhFor === e && m.getAttribute('data-hh-mark') === 'new')); };
      const text = document.querySelector(NEW).textContent;
      W.manifest.releases[${JSON.stringify(PR.past)}] = 'older';
      W.manifest.features.push({ id: 'older-probe', release: ${JSON.stringify(PR.past)}, label: 'Older', what: 'An older feature.', changelog: [], marks: [{ page: ${JSON.stringify(PR.pick.page)}, at: '#wnProbe' }] });
      W.apply();
      const before = { older: has('#wnProbe'), newest: has(NEW), prior: has(OLD) };
      W.manifest.releases[${JSON.stringify(PR.next)}] = 'next';
      W.manifest.features.push({ id: 'next-probe', release: ${JSON.stringify(PR.next)}, label: 'Next', what: 'A newer feature.', changelog: [], marks: [{ page: ${JSON.stringify(PR.pick.page)}, at: '#wnProbe' }] });
      W.apply();
      const after = { next: has('#wnProbe'), newest: has(NEW), prior: has(OLD), sameText: document.querySelector(NEW).textContent === text,
                      renamed: [...document.querySelectorAll('[aria-label]')].filter(e => /\\(new\\)$/.test(e.getAttribute('aria-label'))).length };
      return { before, after };
    })()`);
  }
}

// The marks and the legend keep AA contrast: both themes, glass on and off.
const PAINT = `(() => {
  const rgba = s => { const m = String(s).match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const v = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const behind = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let c = rgba(getComputedStyle(document.documentElement).backgroundColor) || { r: 255, g: 255, b: 255, a: 0 }; c = over(c, { r: 255, g: 255, b: 255, a: 1 }); for (const n of chain.reverse()) { const b = rgba(getComputedStyle(n).backgroundColor); if (b && b.a > 0) c = over(b, c); } return c; };
  return [...document.querySelectorAll('.hh-mark-new, .hh-mark, .wn-legend, .wn-legend-mark')].filter(e => e.getClientRects().length && !e.hidden).map(e => {
    const s = getComputedStyle(e), fg = rgba(s.color), bg = behind(e);
    return { what: e.className + ' in ' + e.parentElement.tagName.toLowerCase() + (e.parentElement.id ? '#' + e.parentElement.id : ''), ratio: Math.round(ratio(over(fg, bg), bg) * 100) / 100, bgClear: !e.classList.contains('hh-mark') || (rgba(s.backgroundColor) || { a: 0 }).a === 0 };
  });
})()`;
for (const theme of ['dark', 'light']) for (const glass of ['on', 'off']) {
  await ev(`(localStorage.setItem('zassess_theme', '${theme}'), localStorage.setItem('zassess_glass', '${glass}'), true)`);
  await open(PR.hidePage);
  out.themes[theme + ' ' + glass] = { glassOff: await ev(`document.documentElement.classList.contains('glass-off')`), light: await ev(`document.body.classList.contains('theme-light')`), marks: await ev(PAINT) };
}
await ev(`(localStorage.removeItem('zassess_glass'), localStorage.setItem('zassess_theme', 'dark'), true)`);

// Hide new marks (Advanced settings): off by default, hides every *, is
// remembered on every page, and brings them back; the ? marks stay. Counted
// on the toured page with the most marks.
const count = () => ev(`(window.HoverHelp.scan(), { marks: document.querySelectorAll('.hh-mark-new:not([hidden])').length, help: document.querySelectorAll('.hh-mark:not(.hh-mark-new)').length, legend: document.querySelectorAll('.wn-legend').length, news: document.querySelectorAll('[data-wn-new]').length, ticked: (document.getElementById('advWnHide') || {}).checked, glassName: document.getElementById('advGlass') ? document.getElementById('advGlass').labels[0].textContent.trim() : '' })`);
const hide = {};
await open(PR.hidePage); hide.start = await count();
await open('/report/advanced'); hide.adv = await count();
await ev(`(document.getElementById('advWnHide').click(), true)`); await frame();
hide.hidden = await count();
await open(PR.hidePage); hide.otherPage = await count();
await open('/report/advanced'); hide.reloaded = await count();
await ev(`(document.getElementById('advWnHide').click(), true)`); await frame();
hide.unticked = await count();
await open(PR.hidePage); hide.shown = await count();
out.hide = hide;

// 320px: nothing scrolls sideways and every mark and legend stays on screen.
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
for (const page of JSON.parse(narrowJson)) {
  await open(page);
  out.narrow[page] = await ev(`(() => { const W = document.documentElement.clientWidth;
    const off = [...document.querySelectorAll('.hh-mark, .wn-legend')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.left >= 0 && r.right > W + 1; }).map(e => e.className + ' in ' + e.parentElement.tagName);
    return { overflow: document.documentElement.scrollWidth - W, off, marks: document.querySelectorAll('.hh-mark-new').length }; })()`);
}
out.errors = seen.errors.splice(0);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def marks_browser(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("new_marks"), DRIVER, json.dumps(_load_marks()), json.dumps(NARROW), json.dumps(PROBES), timeout=240)


def _browser_marks():
    return [(page, m["at"]) for page, ms in _load_marks().items() for m in ms]


@pytest.mark.parametrize("page,at", _browser_marks())
def test_each_mark_renders_with_a_name_that_says_new(marks_browser, page, at):
    """WCAG 2.2 SC 1.3.1 · SC 4.1.2 · SC 1.1.1: a superscript * button sits beside the item, named "New in this version: <item>", with the words on it; the page's own words are unchanged."""
    rec = next(r for r in marks_browser["pages"][page]["marks"] if r["at"] == at)
    assert rec["host"], f"{at} is not on {page}"
    assert rec["star"] and rec["tag"] == "BUTTON" and rec["glyph"] == '"*"' and rec["beside"], rec
    assert (rec["name"] or "").startswith("New in this version: ") and len(rec["name"]) > len("New in this version: "), rec
    assert "*" not in rec["words"] and "(new)" not in rec["words"], "the page's own words (textContent) stay as they were"
    newest = sorted(rec["releases"], reverse=True)
    assert rec["news"].startswith(f"New in the {newest[0]} update: "), rec
    assert all(f"New in the {d} update: " in rec["news"] for d in newest), rec
    assert rec["news"] == expected_words(page, at), rec
    assert rec["news"] in rec["desc"] and rec["expanded"] == "false", "the description screen readers hear carries the same words"


@pytest.mark.parametrize("page", sorted(_load_marks()))
def test_each_page_with_marks_shows_the_legend_and_no_errors(marks_browser, page):
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2: a page with marks explains them ("* New in this version"); the * in the legend is hidden from screen readers."""
    rec = marks_browser["pages"][page]
    assert rec["legend"] and rec["legend"]["text"] == "* New in this version" and rec["legend"]["star"] == "*", rec["legend"]
    assert rec["errors"] == [], rec["errors"]


def _picked(marks_browser):
    got = marks_browser.get("picked") or {}
    assert got.get("new") and got.get("old"), f"no item of each marked release was on screen with its *: {got}"
    return got


def test_the_star_opens_what_is_new_and_the_item_opens_nothing(marks_browser):
    """WCAG 2.2 SC 1.4.13 · SC 3.3.2: pointing at the * of an item from each marked release opens "New in the <date> update: <what>"; pointing at the item itself opens nothing."""
    got, h = _picked(marks_browser), marks_browser["hover"]
    assert h["item"] is None, h["item"]
    for key, at in (("newest", got["new"]), ("older", got["old"])):
        want = expected_words(got["page"], at)
        assert want.startswith(f"New in the {PROBES[key]} update: "), want
        assert h[key] and h[key]["first"] == "hh-new" and h[key]["text"].startswith(want[:120]), (key, at, h[key], want)


def test_the_star_works_from_the_keyboard(marks_browser):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.7 · SC 2.5.8 · SC 3.2.1: focus on the * opens nothing by itself; Enter opens it; it has a visible ring and a 24px target; a marked heading's name says it is new."""
    _picked(marks_browser)
    f = marks_browser["focus"]
    assert f["focusOnly"] is False, "focus alone opens nothing"
    assert f["open"] and f["text"].startswith(f"New in the {PROBES['older']} update") and f["expanded"] == "true", f
    assert f["ring"], "a visible focus ring"
    assert f["w"] >= 24 and f["h"] >= 24, f
    bad = [h for h in marks_browser["headings"] if "New in this version" not in (h["name"] or "")]
    assert not bad, bad


def test_an_item_with_both_marks_has_the_star_then_the_help(marks_browser):
    """WCAG 2.2 SC 1.3.2 (Meaningful Sequence) · SC 4.1.2: an item that is new and needs help gets two buttons, * then ?, each reachable on its own."""
    both = marks_browser["both"]
    assert both, "no marked item on the toured pages also has a ? (help)"
    for b in both:
        kinds = [m.split(":")[0] for m in b["marks"]]
        assert kinds == ["new", "help"], b
        assert b["marks"][0].startswith("new:New in this version: ") and b["marks"][1].startswith("help:Help: "), b


def test_an_older_release_is_not_marked_and_a_new_one_pushes_the_oldest_out(marks_browser):
    """WCAG 2.2 SC 3.2.4 · CWE-1164: a feature older than the marked releases gets no mark; once a newer release is listed, the oldest marked release's marks go and the newest's stay, and no item's words or name change."""
    _picked(marks_browser)
    before, after = marks_browser["rotate"]["before"], marks_browser["rotate"]["after"]
    assert before == {"older": False, "newest": True, "prior": True}, before
    assert after["next"] and after["newest"] and not after["prior"], after
    assert after["sameText"] and after["renamed"] == 0, after


@pytest.mark.parametrize("combo", ["dark on", "dark off", "light on", "light off"])
def test_the_marks_keep_aa_contrast_in_both_themes_with_glass_on_and_off(marks_browser, combo):
    """WCAG 2.2 SC 1.4.3 · SC 1.4.11: in each theme, with the glass on and off, the * and ? marks and the legend keep at least 4.5:1, and a mark has no box of its own."""
    rec = marks_browser["themes"][combo]
    assert rec["light"] == combo.startswith("light") and rec["glassOff"] == combo.endswith("off"), rec
    assert len(rec["marks"]) >= 4, rec
    bad = [m for m in rec["marks"] if not m["bgClear"] or m["ratio"] < 4.5]
    assert not bad, bad


def test_hide_new_marks_hides_them_everywhere_and_is_remembered(marks_browser):
    """WCAG 2.2 SC 3.2.1 · ASVS V7.4.1: "Hide new marks" is off by default, takes every * off on every page (the ? marks stay), survives a reload, and brings them back."""
    h = marks_browser["hide"]
    assert h["adv"]["ticked"] is False and h["start"]["marks"] >= 1 and h["start"]["legend"] == 1, h
    for k in ("hidden", "otherPage", "reloaded"):
        assert h[k]["marks"] == 0 and h[k]["legend"] == 0 and h[k]["news"] == 0 and h[k]["help"] > 0, (k, h[k])
    assert h["reloaded"]["ticked"] is True and h["reloaded"]["glassName"] == "Glass effect"
    assert h["unticked"]["ticked"] is False and h["shown"]["marks"] == h["start"]["marks"]


@pytest.mark.parametrize("page", NARROW)
def test_no_sideways_scroll_at_320px(marks_browser, page):
    """WCAG 2.2 SC 1.4.10 (Reflow): at 320px the marks and the legend stay on screen and the page never scrolls sideways."""
    rec = marks_browser["narrow"][page]
    assert rec["overflow"] <= 0 and rec["off"] == [], rec
    if page in _load_marks():   # a page the newest two releases mark
        assert rec["marks"] >= 1


def test_placing_the_marks_settles(marks_browser):
    """CWE-835 (loop with unreachable exit) · ASVS V11.1.4: on a page with a * and a ? in one title, nothing changes the marks once they are placed (no rescan loop), even when the page's own late content asks for a rescan."""
    assert marks_browser["quiet"] == 0, (marks_browser["quietPage"], marks_browser["quiet"])


def test_the_tour_left_no_script_errors(marks_browser):
    """ASVS V14.1 · CWE-755: the marks add no console error or failed request on any page toured."""
    assert marks_browser["errors"] == []
