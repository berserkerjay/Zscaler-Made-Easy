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
Heal Accept English Guard Branch Palo Alto Networks Bulk Zero Trust Business Cellular Microsegmentation""".split())   # Guard: the product name AI Guard; Palo Alto Networks; Bulk: the Bulk changes page
# Zero Trust Branch, Business Insights, Zero Trust Cellular, Microsegmentation: product names.
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


# ── Wave 6: WCAG 2.2 AA in a real browser, on the sample tenant ──────────
# One headless Chrome (CDP) opens the sample tenant through the Connect
# page, runs the assessment from the Scope page (tests/test_sample_tenant_browser.py
# SETUP), then visits every page the app serves, in the dark and the light
# theme with prefers-reduced-motion on, and measures each one:
#   console errors and HTTP errors on load; an accessible name on every
#   control (Chrome's own accessibility tree, SC 4.1.2); a keyboard walk
#   (focus visible on every stop, SC 2.4.7; focus never stuck, SC 2.1.2);
#   24px targets (SC 2.5.8, with the inline and spacing exceptions); text
#   contrast against what is painted under it (SC 1.4.3); a live region on
#   pages that run jobs (SC 4.1.3); no running animation under reduced
#   motion (SC 2.3.3). The route list is read from the app, so a new page is
#   measured too.

from test_findings_reflow import CDP_PRELUDE, run_in_browser  # noqa: E402
from test_sample_tenant_browser import EVENTS, sample_setup  # noqa: E402


def _browser_routes():
    paths = sorted({r.path for r in srv.app.routes if getattr(r, "methods", None) and "GET" in r.methods and "{" not in r.path
                    and (r.path.startswith("/report/") or r.path in ("/", "/simple", "/help", "/permissions"))})
    refs = ["/reference/" + p["slug"] for p in srv.REFERENCE_PAGES if os.path.exists(os.path.join(STATIC, "reference", p["slug"] + ".html"))]
    assert len(paths) >= 35, paths
    return paths + sorted(refs)


BROWSER_ROUTES = _browser_routes()
BROWSER_THEMES = ("dark", "light")
# Pages that start a job or a read: their progress and result are announced.
JOB_PAGES = {"/report/audit", "/report/browser", "/report/ztw", "/report/device-posture", "/report/digest", "/report/fleet", "/report/insights",
             "/report/live", "/report/logs", "/report/operations", "/report/path", "/report/pov", "/report/shadow",
             "/report/sslcoverage", "/report/zpa", "/report/exports", "/report/self-heal", "/report/posture", "/simple",
             "/report/traffic-logs", "/report/other-products"}

PAGE_AUDIT = r"""(() => {
  // Inside a closed <details> only the summary is shown (Chrome still gives the hidden content a box).
  const shut = e => { const d = e.closest('details:not([open])'); return !!d && !e.closest('summary'); };
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !e.closest('[aria-hidden="true"],[inert]') && !shut(e); };
  const desc = e => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + '.' + String(e.className.baseVal ?? e.className).trim().split(/\s+/).slice(0, 2).join('.') + ' "' + (e.getAttribute('aria-label') || e.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 30) + '"';
  const out = {};
  // SC 2.5.8: 24 by 24 CSS px, or inline in a sentence, or a 24px circle on it touches no other target.
  const sel = 'button, a[href], input:not([type=hidden]), select, textarea, summary, [role=button], [role=tab], [role=checkbox], [role=radio], [role=link]';
  const els = [...document.querySelectorAll(sel)].filter(vis), rects = els.map(e => e.getBoundingClientRect());
  out.small = [];
  els.forEach((e, i) => {
    const r = rects[i]; if (r.width >= 24 && r.height >= 24) return;
    if (getComputedStyle(e).display === 'inline' && e.parentElement && e.parentElement.textContent.trim().length > e.textContent.trim().length + 20) return;
    const lab = e.closest('label') || (e.id && document.querySelector('label[for="' + CSS.escape(e.id) + '"]'));
    if (lab && lab.getBoundingClientRect().height >= 24 && lab.getBoundingClientRect().width >= 24) return;
    const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
    const clash = rects.some((o, j) => j !== i && !els[j].contains(e) && !e.contains(els[j]) && Math.max(o.left - cx, 0, cx - o.right) ** 2 + Math.max(o.top - cy, 0, cy - o.bottom) ** 2 < 144);
    if (clash) out.small.push(desc(e) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
  });
  // SC 1.4.3: the text colour against the colours painted under it (elementsFromPoint, alpha composited).
  // rgb()/rgba(), and color(srgb r g b / a), which color-mix() computes to.
  const rgba = s => { let m = s.match(/rgba?\(([^)]+)\)/); if (m) { const v = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; }
    m = s.match(/color\(srgb\s+([^)]+)\)/); if (m) { const v = m[1].split(/[ \/]+/).filter(Boolean).map(Number); return { r: v[0] * 255, g: v[1] * 255, b: v[2] * 255, a: v.length > 3 ? v[3] : 1 }; }
    return null; };
  const opacity = e => { let o = 1; for (let n = e; n && n.nodeType === 1; n = n.parentElement) o *= parseFloat(getComputedStyle(n).opacity || '1'); return o; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  out.contrast = [];
  // The glass effect (static/glass.css): a glass surface's gradient is its sheen, measured as a layer (not skipped as an
  // image), and the backdrop's colour fields painted over the body's colour are measured too (each field's peak, on either
  // backdrop layer, as well as the plain page).
  const bodyStyle = getComputedStyle(document.body), washOn = ['::before', '::after'].some(p => /gradient/.test(getComputedStyle(document.body, p).backgroundImage));
  const wash = washOn ? [1, 2, 3, 4, 5].map(k => rgba(bodyStyle.getPropertyValue('--glass-amb-' + k))).filter(c => c && c.a > 0) : [];
  const glassOf = ns => (parseInt(ns.getPropertyValue('--glass-surface'), 10) || 0) > 0;
  const texts = [...document.querySelectorAll('body *')].filter(e => [...e.childNodes].some(n => n.nodeType === 3 && n.nodeValue.trim()) && vis(e) && !e.closest('svg, option, [disabled], [aria-disabled="true"], .sr-only'));
  for (const e of texts.slice(0, 1500)) {
    const s = getComputedStyle(e); if (opacity(e) < 0.5) continue;   // faded out, or a dimmed inactive card (SC 1.4.3 exempts inactive components)
    let fg = rgba(s.color); if (!fg || fg.a === 0) continue;
    const r = e.getBoundingClientRect(); const x = Math.min(Math.max(r.left + 2, 0), innerWidth - 1), y = Math.min(Math.max(r.top + Math.min(r.height / 2, 10), 0), innerHeight - 1);
    if (r.bottom < 0 || r.top > innerHeight) { e.scrollIntoView({ block: 'center' }); }
    const r2 = e.getBoundingClientRect();
    if (r2.bottom <= 0 || r2.right <= 0 || r2.top >= innerHeight || r2.left >= innerWidth) continue;   // off screen until focused (a skip link): measured by the focus walk
    // Sample where the text itself is drawn (its own line box), not the element's corner: a capsule's rounded corner is not under its text.
    const tn = [...e.childNodes].find(n => n.nodeType === 3 && n.nodeValue.trim()); const rg = document.createRange(); rg.selectNodeContents(tn);
    const tr = [...rg.getClientRects()].find(q => q.width > 0 && q.height > 0) || r2;
    const px = Math.min(Math.max(tr.left + 2, 0), innerWidth - 1), py = Math.min(Math.max(tr.top + Math.min(tr.height / 2, 10), 0), innerHeight - 1);
    const stack = document.elementsFromPoint(px, py); let i = stack.indexOf(e); if (i < 0) { const k = stack.findIndex(n => e.contains(n) || n.contains(e)); if (k < 0) continue; i = k; }
    const layers = []; let image = false, washed = false;
    for (const n of stack.slice(i)) { const ns = getComputedStyle(n), glass = glassOf(ns); if (!glass && ns.backgroundImage !== 'none' && !/^url\(/.test(ns.backgroundImage) && ns.backgroundImage.includes('gradient')) { image = true; break; } if (n.tagName === 'IMG' || n.tagName === 'VIDEO' || n.tagName === 'CANVAS') { image = true; break; } const c = rgba(ns.backgroundColor);
      const sheen = glass && /linear-gradient/.test(ns.backgroundImage) ? rgba(ns.getPropertyValue('--glass-sheen')) : null;
      if ((c && c.a > 0) || sheen) layers.push({ c: c && c.a > 0 ? c : { r: 0, g: 0, b: 0, a: 0 }, sheen, wash: n === document.body && wash.length > 0 });
      if (n === document.body && wash.length) washed = true;
      if (c && c.a >= 0.999) break; }
    if (image) continue;
    let base = { r: 255, g: 255, b: 255, a: 1 };
    const root = rgba(getComputedStyle(document.documentElement).backgroundColor); if (root && root.a > 0) base = over(root, base);
    // Every way the layers can paint: with and without the sheens, and the plain page or each peak of the wash under the body's content.
    const fg0 = fg; let bg = null, got = 99;
    for (const peak of [null].concat(washed ? wash : [])) for (const withSheen of [false, true]) {
      let b = base;
      for (const l of [...layers].reverse()) { b = over(l.c, b); if (l.wash && peak) b = over(peak, b); if (withSheen && l.sheen) b = over(l.sheen, b); }
      const f = over(fg0, b), r = ratio(f, b);
      if (r < got) { got = r; bg = b; fg = f; }
    }
    const size = parseFloat(s.fontSize), bold = parseInt(s.fontWeight, 10) >= 700, large = size >= 24 || (bold && size >= 18.66);
    const need = large ? 3 : 4.5;
    const hex = c => '#' + [c.r, c.g, c.b].map(v => Math.round(v).toString(16).padStart(2, '0')).join('');
    if (got + 0.02 < need) out.contrast.push(desc(e) + ' ' + got.toFixed(2) + ':1 (' + hex(fg) + ' on ' + hex(bg) + ' under ' + stack.slice(i, i + 4).map(n => n.tagName.toLowerCase() + (n.id ? '#' + n.id : '')).join('<') + ')');
  }
  window.scrollTo(0, 0);
  out.contrast = [...new Set(out.contrast)].slice(0, 12);
  // SC 4.1.2: a control never holds another focusable control (a card that is a button holding a button).
  const FOC = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [tabindex]:not([tabindex="-1"])';
  out.nested = [...document.querySelectorAll('button, a[href], [role=button], [role=link], [role=tab], [role=checkbox], [role=menuitem]')].filter(e => vis(e) && [...e.querySelectorAll(FOC)].some(vis)).map(desc).slice(0, 8);
  // SC 2.1.1: a region that scrolls can be reached by the keyboard (it, or something in it, takes focus).
  out.unreachable = [...document.querySelectorAll('body *')].filter(e => { if (!vis(e) || e.matches(FOC)) return false; const st = getComputedStyle(e);
    const scrolls = (/(auto|scroll)/.test(st.overflowX) && e.scrollWidth > e.clientWidth + 1) || (/(auto|scroll)/.test(st.overflowY) && e.scrollHeight > e.clientHeight + 1);
    return scrolls && ![...e.querySelectorAll(FOC)].some(vis); }).map(desc).slice(0, 8);
  // SC 2.1.1: nothing only a mouse can click (an element with an onclick that takes no focus and holds no control).
  out.clickOnly = [...document.querySelectorAll('body *')].filter(e => (e.hasAttribute('onclick') || typeof e.onclick === 'function') && vis(e) && e.textContent.trim() && !e.matches(FOC) && !e.closest(FOC)
    && !e.querySelector(FOC) && !e.closest('svg') && getComputedStyle(e).pointerEvents !== 'none').map(desc).slice(0, 8);
  // SC 4.1.3: a status or live region the page's progress and results go to.
  out.live = document.querySelectorAll('[role=status],[role=alert],[role=log],[role=progressbar],[aria-live]').length;
  // SC 2.3.3: nothing animates under prefers-reduced-motion.
  out.motion = document.getAnimations().filter(a => a.playState === 'running' && (a.effect && a.effect.getComputedTiming().duration > 50)).map(a => (a.animationName || a.transitionProperty || 'animation') + ' on ' + desc(a.effect.target)).slice(0, 6);
  out.title = document.title; out.lang = document.documentElement.lang;
  out.h1 = document.querySelectorAll('h1').length;
  return out;
})()"""

FOCUS_STEP = r"""new Promise(done => requestAnimationFrame(() => requestAnimationFrame(() => done((() => {
  const el = document.activeElement; if (!el || el === document.body || el === document.documentElement) return null;
  const s = getComputedStyle(el), r = el.getBoundingClientRect();
  // A box-shadow counts as a ring only when it differs from the control's resting shadow (glass buttons rest with a rim and a shadow).
  const rest = window.__ringRest && window.__ringRest.get(el);
  let ring = (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== 'none' && s.boxShadow !== rest);
  if (!ring && el instanceof SVGElement) { const sh = el.querySelector('rect, path, circle'); ring = !!(sh && parseFloat(getComputedStyle(sh).strokeWidth) >= 2); }
  const d = el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + '.' + String(el.className.baseVal ?? el.className).trim().split(/\s+/).slice(0, 2).join('.') + ' "' + (el.getAttribute('aria-label') || el.textContent || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 30) + '"';
  return { d, ring, k: d + '@' + Math.round(r.top + scrollY) + ',' + Math.round(r.left), hidden: r.width === 0 || r.height === 0 };
})()))))"""

A11Y_DRIVER = CDP_PRELUDE + "process.env.UI_DEADLINE_MS = process.env.UI_DEADLINE_MS || '1440000';\n" + EVENTS + "%SETUP%" + r"""
const [routesJson, themesJson, auditJs, focusJs] = args;
const INTERACTIVE = new Set(['button', 'link', 'checkbox', 'radio', 'textbox', 'combobox', 'listbox', 'menuitem', 'tab', 'switch', 'slider', 'spinbutton', 'searchbox', 'DisclosureTriangle', 'menuitemcheckbox', 'menuitemradio', 'option', 'treeitem']);
const out = { run, setupErrors: seen.errors.splice(0), pages: {} };
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('DOM.enable'); await send('Accessibility.enable');
const key = async (k, code, vk, mods = 0) => { await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods }); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods }); };
for (const theme of JSON.parse(themesJson)) {
  await ev(`(localStorage.setItem('zassess_theme', ${JSON.stringify(theme)}), true)`);
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: theme }] });
  for (const route of JSON.parse(routesJson)) {
    seen.errors.splice(0);
    await go(route); await settle(route);
    const rec = out.pages[theme + ' ' + route] = await ev(auditJs);
    rec.errors = seen.errors.splice(0);
    trace(theme, route, 'audited');
    // Chrome's accessibility tree: every control has a name (one query per interactive role).
    const rootId = (await send('DOM.getDocument', { depth: 0 })).result.root.backendNodeId;
    rec.unnamed = [];
    for (const role of INTERACTIVE) {
      const q = await send('Accessibility.queryAXTree', { backendNodeId: rootId, role });
      for (const n of ((q.result || {}).nodes || [])) {
        if (n.ignored || (n.name && String(n.name.value || '').trim())) continue;
        const d = await send('DOM.describeNode', { backendNodeId: n.backendDOMNodeId });
        const node = (d.result || {}).node || {};
        rec.unnamed.push(role + ' <' + String(node.localName || '') + ' ' + (node.attributes || []).join(' ').slice(0, 80) + '>');
      }
    }
    rec.unnamed = rec.unnamed.slice(0, 10);
    if (theme === 'dark') {
      // Keyboard only: Tab through the page.
      await ev(`(document.activeElement && document.activeElement.blur && document.activeElement.blur(), window.scrollTo(0, 0), true)`);
      // Each control's resting box-shadow, taken while nothing has focus: the focus walk below compares against it.
      await ev(`(window.__ringRest = new WeakMap(), document.querySelectorAll('a[href], button, input, select, textarea, summary, [tabindex]').forEach(e => window.__ringRest.set(e, getComputedStyle(e).boxShadow)), true)`);
      const stops = []; const noRing = []; let prev = '', stuck = 0;
      for (let i = 0; i < 250; i++) {
        await key('Tab', 'Tab', 9);
        const f = await ev(focusJs);   // read after the next frame, once the focus ring is drawn
        if (!f) { if (stops.length) break; continue; }
        if (f.k === prev) { if (++stuck >= 3) { rec.trap = f.d; break; } continue; }
        stuck = 0; prev = f.k;
        if (stops.includes(f.k)) break;
        stops.push(f.k);
        if (!f.ring && !f.hidden) noRing.push(f.d);
      }
      rec.stops = stops.length; rec.noRing = [...new Set(noRing)].slice(0, 10);
    }
  }
}
// Result states: each job page run on the sample, then measured again (and at 320 and 390 px).
const [statesJson] = [args[4]];
out.states = {};
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }, { name: 'prefers-color-scheme', value: 'dark' }] });
await ev(`(localStorage.setItem('zassess_theme', 'dark'), true)`);
for (const [name, route, act, ready] of JSON.parse(statesJson)) {
  seen.errors.splice(0);
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await go(route); await settle(route);
  await ev(act);
  const got = await until(() => ev(ready), name + ' result', 180000).catch(() => false);   // ZPA reads are paced
  await settle(name, 4000);
  const rec = out.states[name] = await ev(auditJs);
  rec.ready = !!got; rec.errors = seen.errors.splice(0);
  if (!got) rec.shown = await ev(`(document.querySelector('main') || document.body).innerText.slice(0, 600)`);
  rec.reflow = {};
  for (const width of [320, 390]) {
    await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
    await ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
    rec.reflow[width] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  }
  trace('state', name, rec.ready);
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""

# Each job page with its result on screen: (name, route, the click, the sign the result is drawn).
_SET = "(() => {{ const e = document.getElementById('{0}'); e.value = {1}; e.dispatchEvent(new Event('input', {{ bubbles: true }})); return true; }})()"
RESULT_STATES = [
    ("path-one", "/report/path", _SET.format("paDest", "'chat.openai.com'") + " && document.getElementById('paRun').click() === undefined",
     "!!document.getElementById('paHeadline')"),
    ("path-list", "/report/path#list", _SET.format("plText", "'destination,port,expected\\nchat.openai.com,,block\\nwww.dropbox.com,,allow'")
     + " && document.getElementById('plRun').click() === undefined", "!!document.getElementById('plSummary')"),
    ("shadow", "/report/shadow", "document.getElementById('shRun').click() === undefined", "/rule/i.test(document.querySelector('main').innerText.slice(-4000)) && !document.getElementById('shRun').disabled"),
    ("zpa", "/report/zpa", "document.getElementById('zpRun').click() === undefined", "!document.getElementById('expCsv').hidden"),
    ("ssl-coverage", "/report/sslcoverage", "document.getElementById('scRun').click() === undefined", "!!document.querySelector('#scBody table, main table')"),
    ("device-posture", "/report/device-posture", "document.getElementById('dvRun').click() === undefined", "!document.getElementById('expXlsx').hidden"),
    ("browser-security", "/report/browser", "document.getElementById('bwRun').click() === undefined", "!document.getElementById('expXlsx').hidden"),
    ("cloud-connector", "/report/ztw", "document.getElementById('ztRun').click() === undefined", "!document.getElementById('expXlsx').hidden"),
    ("fleet", "/report/fleet", "document.getElementById('zfRun').click() === undefined", "!!document.querySelector('main table')"),
    ("operations-objects", "/report/operations", "document.getElementById('opRead').click() === undefined", "document.querySelectorAll('#opObjects input[type=checkbox]').length > 0"),
]


@pytest.fixture(scope="module")
def wcag_pages(tmp_path_factory):
    driver = A11Y_DRIVER.replace("%SETUP%", sample_setup())
    return run_in_browser(tmp_path_factory.mktemp("wcag-pages"), driver, json.dumps(BROWSER_ROUTES), json.dumps(BROWSER_THEMES),
                          PAGE_AUDIT, FOCUS_STEP, json.dumps(RESULT_STATES), timeout=1500)


def _page(wcag_pages, theme, route):
    return wcag_pages["pages"][f"{theme} {route}"]


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_every_page_loads_without_errors_on_the_sample(wcag_pages, route):
    """WCAG 2.2 SC 4.1.2 · CWE-754: table over every page: it loads on the sample tenant with no script error, no console error and no HTTP error."""
    assert wcag_pages["run"]["started"], wcag_pages["run"]
    for theme in BROWSER_THEMES:
        assert _page(wcag_pages, theme, route)["errors"] == [], (theme, route)


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_every_control_has_an_accessible_name(wcag_pages, route):
    """WCAG 2.2 SC 4.1.2, 1.3.1 · table over every page: Chrome's accessibility tree gives every button, link, field and tab a name."""
    assert _page(wcag_pages, "dark", route)["unnamed"] == []


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_keyboard_focus_is_visible_and_never_trapped(wcag_pages, route):
    """WCAG 2.2 SC 2.1.1, 2.1.2, 2.4.7 · table over every page: Tab reaches the controls, every stop shows a focus ring, and focus is never stuck."""
    rec = _page(wcag_pages, "dark", route)
    assert rec["stops"] >= 1 and not rec.get("trap"), rec
    assert rec["noRing"] == [], rec["noRing"]


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_every_target_is_at_least_24px(wcag_pages, route):
    """WCAG 2.2 SC 2.5.8 · table over every page: each control is 24 by 24 CSS px, inline in a sentence, or spaced 24px from any other."""
    assert _page(wcag_pages, "dark", route)["small"] == []


@pytest.mark.parametrize("theme", BROWSER_THEMES)
@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_text_contrast_meets_aa_in_both_themes(wcag_pages, route, theme):
    """WCAG 2.2 SC 1.4.3 · table over every page and theme: each text is 4.5:1 (3:1 when large) against what is painted under it."""
    assert _page(wcag_pages, theme, route)["contrast"] == []


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_pages_with_jobs_announce_progress_in_a_live_region(wcag_pages, route):
    """WCAG 2.2 SC 4.1.3 · table over every page: a page that runs a job has a status or live region; every page has a title, a language and one h1."""
    rec = _page(wcag_pages, "dark", route)
    if route in JOB_PAGES:
        assert rec["live"] >= 1, route
    assert rec["title"].strip() and rec["lang"], (route, rec["title"], rec["lang"])
    if not route.startswith("/reference/"):   # the app's own pages; a bundled reference document keeps its own outline
        assert rec["h1"] >= 1, (route, rec["h1"])


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_nothing_animates_under_reduced_motion(wcag_pages, route):
    """WCAG 2.2 SC 2.3.3, 2.2.2 · table over every page: with prefers-reduced-motion on, no animation or transition is running."""
    for theme in BROWSER_THEMES:
        assert _page(wcag_pages, theme, route)["motion"] == [], (theme, route)


@pytest.mark.parametrize("state", [s[0] for s in RESULT_STATES])
def test_every_result_renders_accessibly_and_reflows(wcag_pages, state):
    """WCAG 2.2 SC 1.4.10, 1.4.3, 2.5.8, 4.1.3 · table over the job pages run on the sample: the result is drawn with no error, its text keeps AA contrast, its targets are 24px and it fits 320 and 390 px (the Path analyzer's channel cards were 9px too wide at 320)."""
    rec = wcag_pages["states"][state]
    assert rec["ready"], (state, rec.get("shown"))
    assert rec["errors"] == [] and rec["contrast"] == [] and rec["small"] == [], rec
    assert rec["reflow"] == {"320": 0, "390": 0}, rec["reflow"]


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_no_control_holds_another_control(wcag_pages, route):
    """WCAG 2.2 SC 4.1.2 · table over every page: no button, link or tab holds another focusable control (the reference pages' technique cards were buttons holding a select button)."""
    for theme in BROWSER_THEMES:
        assert _page(wcag_pages, theme, route)["nested"] == [], (theme, route)


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_every_scrolling_region_is_reachable_by_keyboard(wcag_pages, route):
    """WCAG 2.2 SC 2.1.1 · table over every page: a region that scrolls takes focus or holds something that does (the reference pages' timelines and figures did not)."""
    for theme in BROWSER_THEMES:
        assert _page(wcag_pages, theme, route)["unreachable"] == [], (theme, route)


@pytest.mark.parametrize("route", BROWSER_ROUTES)
def test_nothing_is_clickable_only_with_a_mouse(wcag_pages, route):
    """WCAG 2.2 SC 2.1.1, 4.1.2 · table over every page: every element with a click handler takes focus and answers Enter and Space (the reference pages' channel toggles and stat cards were mouse-only)."""
    for theme in BROWSER_THEMES:
        assert _page(wcag_pages, theme, route)["clickOnly"] == [], (theme, route)


# ── Faded steps of the live path: the text keeps AA contrast ─────────────
# The general audit above leaves SVG text out (and anything faded below 0.5),
# so the path boxes for "not reached", "not in scope" and "pending" are
# measured here: they are focusable buttons in the result view, so the
# inactive-component exemption does not apply (WCAG 2.2 SC 1.4.3).

FADED_TONES = ("after", "na", "pend")
FADED_DRIVER = CDP_PRELUDE + r"""
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/path' });
await until(() => ev(`document.readyState === 'complete' && !!window.FA`), 'the path page', 30000);
const out = {};
for (const theme of ['dark', 'light']) {
  out[theme] = await ev(`(() => {
    document.body.classList.toggle('theme-light', ${JSON.stringify(theme)} === 'light');
    const rgba = s => { let m = String(s).match(/rgba?\\(([^)]+)\\)/); if (m) { const v = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; }
      m = String(s).match(/color\\(srgb\\s+([^)]+)\\)/); if (m) { const v = m[1].split(/[ \\/]+/).filter(Boolean).map(Number); return { r: v[0] * 255, g: v[1] * 255, b: v[2] * 255, a: v.length > 3 ? v[3] : 1 }; }
      return null; };
    const over = (f, b, a) => { const k = f.a * a; return { r: f.r * k + b.r * (1 - k), g: f.g * k + b.g * (1 - k), b: f.b * k + b.b * (1 - k), a: 1 }; };
    const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
    const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
    const own = n => parseFloat(getComputedStyle(n).opacity || '1') * parseFloat(getComputedStyle(n).fillOpacity || '1');
    const host = document.createElement('div'); document.querySelector('main').appendChild(host);
    const svg = window.FA.newSvg(host, 640, 60, 'contrast probe');
    // The backdrop: the first painted background above the picture.
    let back = { r: 255, g: 255, b: 255, a: 1 }; const layers = [];
    for (let n = host; n; n = n.parentElement) { const c = rgba(getComputedStyle(n).backgroundColor); if (c && c.a > 0) { layers.push(c); if (c.a >= 0.999) break; } }
    for (const c of layers.reverse()) back = over(c, back, 1);
    const res = {};
    ${JSON.stringify(%TONES%)}.concat(['pass']).forEach((tone, i) => {
      const b = window.FA.box(svg, 10 + i * 150, 4, 140, 46, 'Cloud Firewall', 'not in scope', 'tp-box ' + tone);
      b.g.setAttribute('role', 'button'); b.g.setAttribute('tabindex', '0');
      let group = 1; for (let n = b.g; n && n !== host; n = n.parentElement) group *= parseFloat(getComputedStyle(n).opacity || '1');   // the picture's own fading
      const rect = b.g.querySelector('rect');
      const fill = over(rgba(getComputedStyle(rect).fill) || { r: 0, g: 0, b: 0, a: 0 }, back, own(rect));
      res[tone] = {};
      for (const t of [b.t1, b.t2]) {
        const ink = over(rgba(getComputedStyle(t).fill), fill, own(t));
        // The group's opacity blends text and box alike into the backdrop.
        res[tone][t.getAttribute('class')] = Math.round(100 * ratio(over(ink, back, group), over(fill, back, group))) / 100;
      }
    });
    host.remove();
    return res; })()`);
}
fs.writeFileSync(path.join(dir, 'out.json'), JSON.stringify(out));
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
""".replace("%TONES%", json.dumps(list(FADED_TONES)))


@pytest.fixture(scope="module")
def faded_boxes(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("faded-boxes"), FADED_DRIVER, timeout=120)


@pytest.mark.parametrize("theme", BROWSER_THEMES)
@pytest.mark.parametrize("tone", FADED_TONES)
def test_faded_path_steps_keep_their_text_at_aa_contrast(faded_boxes, theme, tone):
    """WCAG 2.2 SC 1.4.3 (Contrast, Minimum) · SC 1.4.11: a path step drawn as not reached, not in scope or pending fades its shape only; its title and line stay at 4.5:1 or better."""
    got = faded_boxes[theme][tone]
    assert got["fa-t"] >= 4.5 and got["fa-s"] >= 4.5, (theme, tone, got, faded_boxes[theme]["pass"])
