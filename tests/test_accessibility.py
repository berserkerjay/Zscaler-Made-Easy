"""Section 508 / WCAG 2.1 AA structure that the pages must keep: landmarks,
labelled controls, real buttons for toggles, keyboard-operable diagrams,
reduced-motion rules and a skip link. The full axe-core audit runs in a
browser (see docs/ACCESSIBILITY.md); these checks guard the markup."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


def test_main_page_structure():
    html = _read("index.html")
    assert 'class="skip-link"' in html and 'id="main-content"' in html
    assert "prefers-reduced-motion" in html and ":focus-visible" in html
    # Every select in the static markup has an accessible name (label[for], aria-label or aria-labelledby).
    for m in re.finditer(r"<select\s+id=\"([^\"]+)\"([^>]*)>", html):
        sid, attrs = m.group(1), m.group(2)
        assert ("aria-label" in attrs or "aria-labelledby" in attrs or f'for="{sid}"' in html), f"select #{sid} has no accessible name"
    # Collapsible cards toggle through a real button, never a heading with a role.
    assert "btn.className = 'card-toggle'" in html and "h.setAttribute('role', 'button')" not in html
    assert ".card-toggle:focus-visible" in html
    # Primary buttons use the darker button token (white text at 4.5:1) and dark wells use a token.
    assert "--btn:" in html and "--well:" in html and "rgba(15,23,42,0.6)" not in html


def test_report_pages_have_landmarks_and_headings():
    for name in ("report_view.html", "report_flow.html", "report_dataflow.html", "report_sslflow.html", "report_bypass.html"):
        html = _read(name)
        assert '<header class="hero rp-hero">' in html, name
        assert '<nav class="rp-bar" aria-label="Report actions">' in html and "</nav>" in html, name
        assert "<main" in html, name
        assert "<h1>" in html or "<h1 " in html, name
    df = _read("report_dataflow.html") + _read("data_flow.js")
    assert "<h3" not in df, "data flow tab uses h2 under the page h1"
    for name in ("report_logs.html", "help.html", "report_evalall.html", "report_digest.html", "report_path.html", "report_live.html"):
        html = _read(name)
        assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html, name
        assert "<main" in html and ("<h1>" in html or "<h1 " in html), name
        if name in ("report_logs.html", "report_digest.html", "report_path.html", "report_live.html"):
            assert 'role="status"' in html and 'aria-live' in html, "the analyzer announces progress and results"


def test_log_analyzer_page_is_operable_without_a_mouse():
    html = _read("report_logs.html")
    assert '<label for="laFiles">' in html and 'id="laFiles"' in html, "the file input has a visible label"
    assert 'aria-describedby="laHow laLimit"' in html, "the input is described by the how-to and the limit"
    assert 'id="liveRegion" class="sr-only" role="status" aria-live="polite"' in html
    assert "aria-disabled" in html and 'type="button"' in html
    assert "summary:focus-visible" in html and "prefers-reduced-motion" in html
    assert '<th scope="col">' in html, "data tables have column headers"
    assert "<h3" in html and "<h2" in html and html.index("<h2") < html.index("<h3"), "headings nest h1 > h2 > h3"
    js = _read("explain.js")
    assert "summary:focus-visible" in js and ".xp-link:focus-visible" in js, "the explainer box is keyboard-visible"
    assert 'aria-labelledby' in js and "<details" in js


def test_diagrams_are_keyboard_operable():
    dz = _read("deploy_studio.js")
    assert 'tabindex="0" role="img"' in dz and "_dzFlowKey" in dz
    df = _read("data_flow.js")
    assert 'tabindex="0" role="button"' in df and "e.key === 'Enter' || e.key === ' '" in df
    assert '<header class="dz-head">' not in dz    # a dialog head is not a page banner


def test_guide_progress_and_permissions_page():
    g = _read("guide.js")
    assert 'role="progressbar"' in g and 'aria-valuenow="${doneCount}"' in g
    c = TestClient(srv.app)
    page = c.get("/permissions").text
    assert 'class="endpoints" tabindex="0"' in page


def test_reduced_motion_and_light_theme_contrast_rules_exist():
    assert "prefers-reduced-motion" in _read("reports.css") and "prefers-reduced-motion" in _read("deploy_studio.css")
    assert "body.theme-light .df-chip.st-ok" in _read("reports.css")
    assert "var(--btn, #2563eb)" in _read("reports.css") and "var(--btn, #2563eb)" in _read("deploy_studio.css")
    assert "var(--btn, #2563eb)" in _read("guide.css")


# ── QA wave: WCAG 2.2 AA regressions (contrast tokens, fills, motion,
# targets, headings, sentence case). Deterministic and offline: the token
# values are read from the stylesheet itself and the contrast is computed
# with the WCAG formula, so a token edit that breaks 4.5:1 fails here. ──
import html as _html
import json
import shutil
import subprocess

import pytest

THEMES = ("dark", "light")
SURFACES = ("bg", "card", "card-solid", "well")
TEXT_TOKENS = ("text", "dim", "info", "accent", "pass", "warn", "fail",
               "chip-ok", "chip-warn", "chip-fail", "chip-info", "chip-purple")
SEMANTIC = ("accent", "pass", "warn", "fail", "chip-ok", "chip-warn", "chip-fail", "chip-info", "chip-purple")
FILLS = ("btn", "btn-hover", "btn-danger", "btn-warn", "btn-ok")


def _tokens():
    """{theme: {name: '#rrggbb'}} from the first <style> of index.html (app.css)."""
    css = _read("index.html").split("<style>", 1)[1].split("</style>", 1)[0]
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    light = css.split("body.theme-light {", 1)[1].split("}", 1)[0]
    parse = lambda block: dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", block))
    dark = parse(root)
    return {"dark": dark, "light": {**dark, **parse(light)}}


def _lum(hexc):
    r, g, b = (int(hexc[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _contrast(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _mix(fg, bg, p):
    """color-mix(in srgb, fg p, bg)."""
    return "#" + "".join("%02x" % round(int(fg[i:i + 2], 16) * p + int(bg[i:i + 2], 16) * (1 - p)) for i in (1, 3, 5))


@pytest.mark.parametrize("fg,bg,expected", [
    ("#000000", "#ffffff", 21.0),     # the maximum
    ("#777777", "#777777", 1.0),      # the minimum
    ("#767676", "#ffffff", 4.54),     # the classic AA boundary grey passes...
    ("#777777", "#ffffff", 4.48),     # ...and one step lighter fails
])
def test_contrast_formula_matches_the_wcag_definition(fg, bg, expected):
    """WCAG 2.2 SC 1.4.3 · the contrast ratio the token checks use is the WCAG relative-luminance formula."""
    assert round(_contrast(fg, bg), 2) == expected


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("token", TEXT_TOKENS)
def test_text_tokens_meet_aa_contrast_in_both_themes(theme, token):
    """WCAG 2.2 SC 1.4.3 · every text token is at least 4.5:1 on the page, the card and the well, in both themes."""
    t = _tokens()[theme]
    for surface in SURFACES:
        ratio = _contrast(t[token], t[surface])
        assert ratio >= 4.5, f"{theme} --{token} {t[token]} on --{surface} {t[surface]} is {ratio:.2f}:1"
    if token in ("text", "dim"):
        assert _contrast(t[token], t["well-2"]) >= 4.5, f"{theme} --{token} on --well-2"


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("token", SEMANTIC)
def test_semantic_text_is_readable_on_its_own_chip_tint(theme, token):
    """WCAG 2.2 SC 1.4.3 · a status chip (its colour on its own 12% tint of the card or page) keeps 4.5:1."""
    t = _tokens()[theme]
    for surface in ("card-solid", "bg"):
        chip = _mix(t[token], t[surface], 0.12)
        assert _contrast(t[token], chip) >= 4.5, f"{theme} --{token} on its tint over --{surface}"
    # --dim captions sit on the accent tint (selected rows, the intro box).
    assert _contrast(t["dim"], _mix(t["accent"], t["card-solid"], 0.12)) >= 4.5


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("fill", FILLS)
def test_white_text_on_every_fill_token_meets_aa(theme, fill):
    """WCAG 2.2 SC 1.4.3 · white button text is at least 4.5:1 on every fill token, in both themes."""
    t = _tokens()[theme]
    assert _contrast("#ffffff", t[fill]) >= 4.5, f"white on {theme} --{fill} {t[fill]}"


def _ui_sources():
    """Every first-party stylesheet, page and script (reference pages carry their own palette)."""
    names = sorted(n for n in os.listdir(STATIC) if n.endswith((".css", ".html", ".js")))
    return [n for n in names if n not in ("icons.js",)]


WHITE_ON_SEMANTIC = re.compile(
    r"background(?:-color)?:\s*var\(--(?:accent|pass|warn|fail|info)\b[^;\"}]*[;\"]?[^{}\"]{0,120}?color:\s*(?:#fff\b|#ffffff|white)"
    r"|color:\s*(?:#fff\b|#ffffff|white)[^{}\"]{0,120}?background(?:-color)?:\s*var\(--(?:accent|pass|warn|fail|info)\b")


@pytest.mark.parametrize("name", _ui_sources())
def test_white_text_sits_only_on_fill_tokens(name):
    """WCAG 2.2 SC 1.4.3 · white text never sits on a text-colour token (--accent, --pass, --warn, --fail): fills use --btn*."""
    hits = [m.group(0)[:120] for m in WHITE_ON_SEMANTIC.finditer(_read(name))]
    assert not hits, f"{name}: white text on a text-colour token: {hits}"


def test_the_white_on_semantic_scan_catches_the_old_fills():
    """WCAG 2.2 SC 1.4.3 · negative case: the scan above flags the fills this wave replaced."""
    for old in (".db-item[aria-current=\"page\"] { color: #fff; background: var(--accent); }",
                ".btn.danger { background: var(--fail); color: #fff; }",
                'style="background:var(--fail);color:white;border:0;"'):
        assert WHITE_ON_SEMANTIC.search(old), old
    assert not WHITE_ON_SEMANTIC.search(".btn.danger { background: var(--btn-danger); color: #fff; }")


def test_a_hovered_primary_button_keeps_its_fill_in_the_light_theme():
    """WCAG 2.2 SC 1.4.3 · in the light theme a hovered primary button keeps its fill (white text was on --well, 1.1:1)."""
    css = _read("reports.css")
    assert "body.theme-light .rp-btn:hover {" not in css
    assert "body.theme-light .rp-btn:not(.primary):hover { background: var(--well); }" in css


@pytest.mark.parametrize("rule", [".df-chip.st-ok", ".df-chip.st-warn", ".df-chip.st-fail", ".adv-page .chip.ok", ".adv-page .chip.warn", ".adv-page .chip.bad"])
def test_status_chips_tint_into_the_card_not_the_surface_below(rule):
    """WCAG 2.2 SC 1.4.3 · a status chip mixes 12% of its colour into the opaque card, so a well or tinted row under it cannot drop it below 4.5:1."""
    css = _read("reports.css")
    body = css.split(rule + " {", 1)[1].split("}", 1)[0]
    assert re.search(r"color-mix\(in srgb, var\(--(pass|warn|fail)\) 12%, var\(--card-solid\)\)", body), body
    assert "transparent" not in body


SCROLL_GUARD_START = "// Reduced motion covers scripted scrolling too (WCAG 2.3.3)"


def _scroll_guard():
    js = _read("report_theme.js")
    assert SCROLL_GUARD_START in js
    return js[js.index(SCROLL_GUARD_START):]


def test_every_page_carries_the_reduced_motion_scroll_guard():
    """WCAG 2.2 SC 2.3.3 · every page that scrolls from script (report tabs, Simple mode, the assessment page) turns smooth scrolling off under reduced motion."""
    guard = _scroll_guard()
    assert guard.strip() in _read("index.html"), "the assessment page carries the same guard inline"
    for name in sorted(n for n in os.listdir(STATIC) if n.endswith(".html") and n != "index.html"):
        assert '<script src="/static/report_theme.js"></script>' in _read(name), name


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("reduce,behavior,expected", [
    (True, "smooth", "auto"),       # the preference is on: instant
    (False, "smooth", "smooth"),    # the preference is off: untouched
    (True, "instant", "instant"),   # other behaviours are left alone
    (True, None, None),             # a call without options is passed through as is
])
def test_the_scroll_guard_turns_smooth_into_instant_only_under_reduced_motion(reduce, behavior, expected):
    """WCAG 2.2 SC 2.3.3 · the guard rewrites behavior 'smooth' to 'auto' while prefers-reduced-motion is on, and nothing else."""
    harness = """
      const seen = [];
      function El() {}
      El.prototype.scrollIntoView = function (o) { seen.push(o); };
      El.prototype.scroll = El.prototype.scrollTo = El.prototype.scrollBy = El.prototype.scrollIntoView;
      global.Element = El;
      global.window = { matchMedia: q => ({ matches: REDUCE && q === '(prefers-reduced-motion: reduce)' }),
                        scrollTo(o) { seen.push(o); }, scroll(o) { seen.push(o); }, scrollBy(o) { seen.push(o); } };
      GUARD
      const opt = BEHAVIOR === null ? undefined : { behavior: BEHAVIOR, block: 'start' };
      new El().scrollIntoView(opt); window.scrollTo(opt);
      process.stdout.write(JSON.stringify(seen.map(o => o === undefined ? null : o.behavior)));
    """.replace("REDUCE", json.dumps(reduce)).replace("BEHAVIOR", json.dumps(behavior)).replace("GUARD", _scroll_guard())
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=10)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == [expected, expected]


def test_disclosures_are_24px_targets():
    """WCAG 2.2 SC 2.5.8 · every <summary> on a report page is a target at least 24px tall."""
    assert re.search(r"(^|\n)summary \{ min-height: 24px; \}", _read("reports.css"))
    for name in sorted(n for n in os.listdir(STATIC) if n.startswith("report_") and n.endswith(".html")):
        html = _read(name)
        if "<summary" in html:
            assert '/static/reports.css' in html, name


def test_headings_never_skip_a_level_where_this_wave_found_it():
    """WCAG 2.2 SC 1.3.1 · the dashboard tiles (h3) sit under an h2, the migration cross-reference uses h3 under its h2."""
    dash = _read("dashboard.js")
    assert dash.index('<h2 class="sr-only">Dashboard</h2>') < dash.index('<h3 class="db-tile-t">Overall maturity score</h3>')
    vendor = _read("report_vendor.html")
    assert "<h4" not in vendor and "<h3>Export file types accepted</h3>" in vendor


def test_heading_levels_in_static_markup_never_skip():
    """WCAG 2.2 SC 1.3.1 · table-driven: in every page's static markup no heading is more than one level below the one before it."""
    for name in sorted(n for n in os.listdir(STATIC) if n.endswith(".html")):
        markup = re.sub(r"<script\b.*?</script>", "", _read(name), flags=re.S)
        levels = [int(m) for m in re.findall(r"<h([1-6])\b", markup)]
        jumps = [(a, b) for a, b in zip(levels, levels[1:]) if b > a + 1]
        assert not jumps, f"{name}: heading jumps {jumps}"


def test_aria_roles_on_named_regions():
    """WCAG 2.2 SC 4.1.2 · an aria-label sits on an element with a role (the maturity band), and the scrolling path stage is keyboard-focusable (SC 2.1.1)."""
    assert '<div class="db-band" id="dbBand" role="group" aria-label="Maturity band">' in _read("dashboard.js")
    assert '<div class="pm-wrap" id="pmStage" tabindex="0" role="region" aria-label="' in _read("path_motion.js")
    assert ".fl-find input:focus { outline: none" not in _read("reports.css"), "the find field keeps the focus ring (SC 2.4.7)"


# Sentence case (the interface guide): product names keep their capitals.
PROPER = frozenset("""Zscaler ZIA ZPA ZCC ZDX ZIdentity DLP SSL TLS SaaS API APIs OneAPI Terraform Workflow Automation Client
Connector Connectors Excel JSON CSV PDF HTML Word Markdown URL URLs IP IPs DNS PAC EDR CASB AI GenAI Microsoft Google
Chrome Edge Windows Insights HTTP HTTPS QUIC ID IDs OAuth SCIM SAML IdP OK PII PHI PCI Box Dropbox Slack Okta Entra
Azure AWS Teams Zoom ChatGPT Copilot Firefox Safari Opera Internet Explorer Mobile Portal Cloud App Control File Type
Firewall Browser Isolation Private Access Remote Privileged Evaluate All Rules Made Easy Simple Find Review Scope
Symantec Broadcom Forcepoint Netskope Skyhigh Purview Ansible SDK Ctrl Cmd Enter Esc Tab Shift Letter Git Jira
Data Security Architect Portfolio Framework Inline Web Endpoint Email Advanced Settings Secure Design CISA I Shadow
Heal Accept English Branch""".split())
_LABEL_TAGS = "h1|h2|h3|h4|h5|h6|button|th|title|legend|summary"
_START_TAG = r"(?:[^>\"']|\"[^\"]*\"|'[^']*')*"


def _title_case_words(text):
    """Capitalised words that are not the first of a sentence or a product name."""
    t = _html.unescape(re.sub(r"<[^>]+>", " ", text))
    t = re.sub(r"\bOpen (the )?", "Open: ", t)   # "Open <page name>" starts the page's own name
    bad = []
    for part in re.split(r"[:—.;?!·(]\s+|\s[–-]\s|\(", t):
        words = re.findall(r"[A-Za-z][\w'-]*", part)
        bad += [w for w in words[1:] if re.fullmatch(r"[A-Z][a-z]+", w) and w not in PROPER]
    return bad


def _title_case_labels(src):
    found = []
    for m in re.finditer(rf"<({_LABEL_TAGS})\b{_START_TAG}>(.*?)</\1>", src, re.S):
        inner = m.group(2)
        if "${" in inner or "<" in re.sub(r"</?(span|strong|b|em|code|abbr)\b[^>]*>", "", inner):
            continue
        if _title_case_words(inner):
            found.append(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", inner)).strip()[:80])
    found += [m.group(1)[:80] for m in re.finditer(r'aria-label="([^"$]+)"', src) if _title_case_words(m.group(1))]
    return found


@pytest.mark.parametrize("text,bad", [
    ("Required API Access per Assessment Scope", ["Assessment"]),   # "Access" and "Scope" are also names (Private Access, the Scope page)
    ("Zscaler Best practices Library", ["Best", "Library"]),
    ("Guided Next", ["Next"]),
    ("Required API access per assessment scope", []),
    ("Open Traffic flow and gaps: the path through Client Connector and ZIA", []),
    ("Cloud App Control and File Type Control in Zscaler Made Easy", []),
])
def test_the_sentence_case_check_tells_names_from_title_case(text, bad):
    """WCAG 2.2 SC 3.2.4 (consistent identification) · interface guide: the sentence-case check flags Title Case and keeps product names (positive and negative cases)."""
    assert _title_case_words(text) == bad


def _pages():
    return sorted(n for n in os.listdir(STATIC) if n.endswith(".html")) + ["find_anything.js", "posture_banner.js", "dashboard.js"]


@pytest.mark.parametrize("name", _pages())
def test_labels_headings_and_buttons_use_sentence_case(name):
    """WCAG 2.2 SC 3.2.4 (consistent identification) · interface guide: table-driven over every page: headings, buttons, table headers, titles and aria-labels use sentence case."""
    assert _title_case_labels(_read(name)) == [], name


def test_the_api_access_page_and_scope_names_use_sentence_case():
    """WCAG 2.2 SC 3.2.4 (consistent identification) · interface guide: the Required API access page (served from Python) and its scope names use sentence case."""
    page = TestClient(srv.app).get("/permissions").text
    assert _title_case_labels(page) == []
    assert "<title>Required API access · Zscaler Made Easy</title>" in page


@pytest.mark.parametrize("name,needle", [
    ("index.html", "linear-gradient(90deg,var(--accent),#60a5fa)"),
    ("deploy_studio.js", "backdrop-filter:blur("),
    ("dashboard.js", "linearGradient"),
])
def test_no_gradient_or_blur_left_in_the_interface(name, needle):
    """WCAG 2.2 SC 1.4.3, 1.4.11 · interface guide: no gradients or blur (the wizard bar, the Terraform dialog backdrop, the score ring)."""
    assert needle not in _read(name)


def test_the_find_dialog_results_region_is_keyboard_scrollable():
    """WCAG 2.2 SC 2.1.1, 2.4.7 · the Find anything results scroll in a focusable, named region with a visible focus ring."""
    js = _read("find_anything.js")
    assert "h('div', { class: 'fa-body', id: 'faBody', tabindex: '0', role: 'region', 'aria-label': 'Find anything results' }, listEl)" in js
    assert ".fa-body:focus-visible{outline:2px solid var(--accent)" in js
    # The focus trap counts it, so Tab and Shift+Tab still cycle inside the dialog.
    assert "dlg.querySelectorAll('button, [href], input, textarea, select, [tabindex]:not([tabindex=\"-1\"])')" in js
