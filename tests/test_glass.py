"""The glass effect (static/glass.css, static/glass.js, and the extension's
browser_extension/glass.css): one shared material over a living backdrop of
soft colour fields, its solid and still fallbacks, its wiring on every page,
and the WCAG 2.2 AA contrast of text on it, computed against the worst case
behind each tier (the brightest and darkest point of the colour fields
included).

Static and deterministic: the material's numbers are read from glass.css and
the theme tokens from app.css (the first <style> of index.html), and every
colour-mix() is evaluated here with the CSS formula, so an edit that makes a
surface too see-through fails. The switch's storage logic runs in node with a
stub DOM. The real-browser checks are in tests/test_glass_browser.py."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

import dlp_api_server as srv
from test_accessibility import TEXT_TOKENS, _tokens

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


CSS = _read("glass.css")
CSS_NO_COMMENTS = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)


def _block(css, head):
    """The body of the first block whose prelude is exactly `head` (braces balanced)."""
    i = css.index(head + " {")
    j = depth = css.index("{", i)
    depth = 0
    for k in range(j, len(css)):
        depth += {"{": 1, "}": -1}.get(css[k], 0)
        if depth == 0:
            return css[j + 1:k]
    raise AssertionError(head)


def _decls(block):
    return dict((k.strip(), v.strip()) for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block))


# ── The solid fallbacks ─────────────────────────────────────────────────

FALLBACKS = [
    "@media (prefers-reduced-transparency: reduce)",
    "@media (prefers-contrast: more)",
    "@media (forced-colors: active)",
    "@media print",
    "@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px)))",
]
ALPHAS = sorted(k for k in _decls(_block(CSS_NO_COMMENTS, "body")) if k.startswith("--glass-a-"))


@pytest.mark.parametrize("head", FALLBACKS)
def test_every_fallback_turns_the_glass_solid(head):
    """WCAG 2.2 SC 1.4.3, 1.4.11 · CSS Media Queries 5 (prefers-reduced-transparency, prefers-contrast, forced-colors), print and no backdrop-filter support: glass.css defines a solid, unblurred fallback for each."""
    # Arrange
    body = _block(CSS_NO_COMMENTS, head)
    # Act
    decls = _decls(body)
    # Assert
    assert decls.get("--glass-solid-filter") == "none", head
    assert decls.get("--glass-solid-img") == "none", head
    assert decls.get("--glass-solid-motion") == "none", (head, "the backdrop stands still too")
    assert len(ALPHAS) >= 5 and all(decls.get(a) == "100%" for a in ALPHAS), (head, {a: decls.get(a) for a in ALPHAS})
    assert re.search(r"body, body\.theme-light, body\.has-portrait, body\.has-logo\s*\{", body), "covers both themes and the branding override"


@pytest.mark.parametrize("head", ["@media print", "@media (forced-colors: active)", "@media (prefers-contrast: more)"])
def test_print_contrast_and_forced_colours_also_drop_the_shadows(head):
    """WCAG 2.2 SC 1.4.11 · SC 1.4.3: plain surfaces for print, more contrast and forced colours: no drop shadow, no rim."""
    assert _decls(_block(CSS_NO_COMMENTS, head)).get("--glass-solid-shadow") == "none"


def test_reduced_motion_stops_the_drift_and_the_pointer_lens():
    """WCAG 2.2 SC 2.3.3 · SC 2.2.2 (pause, stop, hide): under prefers-reduced-motion the backdrop's drift is switched off (--glass-solid-motion: none) and the pointer-follow highlight is transparent."""
    decls = _decls(_block(CSS_NO_COMMENTS, "@media (prefers-reduced-motion: reduce)"))
    assert decls.get("--glass-solid-motion") == "none" and decls.get("--glass-lens-on") == "transparent", decls
    js = _read("glass.js")
    assert "'(prefers-reduced-motion: reduce)'" in js and "requestAnimationFrame(draw)" in js


def test_only_the_backdrop_moves_slowly_and_through_its_switch():
    """WCAG 2.2 SC 2.2.2, 2.3.1 · performance: the only animation is the backdrop's drift: on the two backdrop layers, through --glass-solid-motion (so every fallback and reduced motion stop it), slow (60 s or more per cycle), stepped (a few updates a second) and transform-only (compositor, no layout or paint); no transition anywhere."""
    # Arrange
    uses = re.findall(r"(?<![\w-])animation\s*:\s*([^;]+);", CSS_NO_COMMENTS)
    frames = re.findall(r"@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^{}]*\})*)\s*\}", CSS_NO_COMMENTS)
    drift = float(_decls(_block(CSS_NO_COMMENTS, "body"))["--glass-drift"].rstrip("s"))
    # Act
    props = {p.strip() for _, body in frames for p in re.findall(r"([\w-]+)\s*:", body)}
    # Assert
    assert len(uses) == 2 and all(u.startswith("var(--glass-solid-motion, glass-drift-") and re.search(r"steps\(\d+\)", u) for u in uses), uses
    assert len(frames) == 2 and props == {"transform"}, (frames, props)
    assert drift >= 60
    assert not re.search(r"\btransition\s*:", CSS_NO_COMMENTS)
    for m in re.finditer(r"([^{}]+)\{[^{}]*(?<![\w-])animation\s*:", CSS_NO_COMMENTS):
        assert all(re.search(r"body:not\(\.has-(portrait|logo)\)::(before|after)$", part.strip()) for part in _top_level_parts(m.group(1))), m.group(1)


def test_the_drift_pauses_while_the_tab_is_hidden():
    """WCAG 2.2 SC 2.2.2 · performance (no work for a hidden tab): glass.js sets html.glass-still on visibilitychange while the page is hidden, and glass.css pauses both backdrop layers on it."""
    js = _read("glass.js")
    assert "document.addEventListener('visibilitychange', still);" in js
    assert "root.classList.toggle('glass-still', document.visibilityState === 'hidden')" in js
    body = _block(CSS_NO_COMMENTS, ":root:not(.glass-off).glass-still body::before,\n:root:not(.glass-off).glass-still body::after")
    assert "animation-play-state: paused" in body


def test_a_blurred_card_is_never_taller_than_the_window():
    """Performance (a GPU render surface the size of the page) · WCAG 2.2 SC 1.4.10: cards and the assessment page's dialog cards are blurred only with .glass-fit, which glass.js gives a surface no taller than the window (ResizeObserver, no per-frame work); unmeasured means unblurred."""
    # Arrange
    rules = re.findall(r"([^{}]+)\{([^{}]*backdrop-filter:\s*var[^{}]*)\}", CSS_NO_COMMENTS)
    # Act
    card_rules = [p for p, _ in rules if re.search(r"\.rp-card|\.card\b|xp-details|Modal", p)]
    # Assert
    assert card_rules and all(p.strip().endswith(".glass-fit") for p in card_rules), card_rules
    assert ":root:not(.glass-off) .db-modal-card:not(.glass-fit) { -webkit-backdrop-filter: none; backdrop-filter: none; }" in CSS_NO_COMMENTS
    js = _read("glass.js")
    assert "el.classList.toggle('glass-fit', h > 0 && h <= window.innerHeight);" in js
    assert "new window.ResizeObserver(" in js and "setTimeout(scan, 200)" in js


def test_every_blur_sheen_and_shadow_goes_through_its_solid_switch():
    """WCAG 2.2 SC 1.4.3 · CSS Media Queries 5: every backdrop-filter, background-image and box-shadow of the material can be switched off by the fallbacks (no rule bypasses them)."""
    # Arrange
    rules = re.sub(r"@supports[^{]*\{", "{", CSS_NO_COMMENTS)   # the feature test itself is not a declaration
    decls = re.findall(r"(?<![\w-])(-webkit-backdrop-filter|backdrop-filter|background-image|box-shadow)\s*:\s*([^;]+);", rules)
    switch = {"-webkit-backdrop-filter": "var(--glass-solid-filter,", "backdrop-filter": "var(--glass-solid-filter,",
              "background-image": "var(--glass-solid-img,", "box-shadow": "var(--glass-solid-shadow,"}
    # Act
    bad = [(p, v[:60]) for p, v in decls if not v.startswith(switch[p]) and v not in ("none", "none !important")]   # "none" only ever takes glass away
    # Assert
    assert len(decls) >= 20 and not bad, bad


def _top_level_parts(selector):
    """A selector list split at its top-level commas (not those inside :is() or :not())."""
    parts, depth, cur = [], 0, ""
    for ch in selector:
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            parts.append(cur); cur = ""
        else:
            cur += ch
    return parts + [cur]


def test_every_glass_rule_is_behind_the_viewer_switch():
    """WCAG 2.2 SC 1.4.12 / user preference · CISA Secure by Design (secure defaults, user choice): every rule that styles a surface is gated by :root:not(.glass-off), so the Advanced settings switch turns all of it off."""
    # Arrange: top-level rules outside @property, the token blocks and the @media / @supports fallbacks
    top, depth, start, preludes = CSS_NO_COMMENTS, 0, 0, []
    for k, ch in enumerate(top):
        if ch == "{":
            if depth == 0:
                preludes.append(top[start:k].strip())
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                start = k + 1
    # Act
    rules = [p for p in preludes if not p.startswith(("@property", "@media", "@supports", "@keyframes"))
             and p not in ("body", "body.theme-light", "body.has-portrait, body.has-logo")]
    # Assert
    assert len(rules) >= 20
    for p in rules:
        assert all(part.strip().startswith(":root:not(.glass-off)") for part in _top_level_parts(p)), p


@pytest.mark.parametrize("name", ["glass.css", "glass.js"])
def test_no_colour_literals_only_theme_tokens(name):
    """WCAG 2.2 SC 1.4.3 · interface guide: the material mixes the theme tokens; it defines no colour of its own (no hex, no rgb())."""
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", _read(name), flags=re.S)
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", text) and not re.search(r"\brgba?\(|\bhsla?\(", text)


def test_tables_stay_near_opaque_and_are_never_blurred():
    """WCAG 2.2 SC 1.4.3 · performance: dense data keeps a near-opaque surface (97% or more) and no table is given a backdrop blur."""
    alpha = float(_decls(_block(CSS_NO_COMMENTS, "body"))["--glass-a-dense"].rstrip("%"))
    assert alpha >= 95
    for prelude, body in re.findall(r"([^{}]+)\{([^{}]*)\}", CSS_NO_COMMENTS):
        if re.search(r"\btable\b|\.tw\b|tablewrap", prelude):
            assert "backdrop-filter" not in body and "var(--glass-dense-bg)" in body, prelude


# ── Wiring: every page gets the layer the way the other add-ons do ──────

def _app_pages():
    return sorted(n for n in os.listdir(STATIC) if n.endswith(".html") and 'href="/app.css"' in _read(n))


def test_the_home_page_gets_the_glass_through_gui_addons():
    """ASVS V14.4 · WCAG 2.2 SC 1.4.3: glass.css is a GUI add-on style (last, so it layers over the others) and glass.js a head script, injected before </head>."""
    # Arrange
    names = [n for n, _ in srv.GUI_ADDONS]
    # Act
    html = srv._inject_gui_addons(_read("index.html"))
    head = html[:html.find("</head>")]
    # Assert
    assert ("glass.css", "style") in srv.GUI_ADDONS and ("glass.js", "head-script") in srv.GUI_ADDONS
    styles = [n for n, k in srv.GUI_ADDONS if k == "style"]
    assert styles[-1] == "glass.css"
    assert "/static/glass.css?v=" in head and "/static/glass.js?v=" in head, "both are in the document head, before the first paint"
    assert names.index("sidebar_order.js") + 1 == names.index("dashboard.js") == len(names) - 1, "the existing order is kept"


def test_a_head_script_is_never_put_at_the_end_of_the_body():
    """ASVS V14.4 · CWE-1041: the head-script kind lands before the document's own </head>, the other scripts before its last </body>."""
    page = "<html><head><title>t</title></head><body><script>var s = '</head></body>';</script></body></html>"
    out = srv._inject_gui_addons(page)
    assert out.index("<title>t</title>") < out.index("/static/glass.js") < out.index("</head>") < out.index("<body>")
    assert out.rindex("/static/dashboard.js") > out.index("var s =")


def test_reports_css_imports_the_glass_before_any_rule():
    """ASVS V14.4 · CSS Cascade 4 (an @import after a rule is ignored): every page that loads reports.css loads glass.css."""
    css = re.sub(r"/\*.*?\*/", "", _read("reports.css"), flags=re.S).lstrip()
    assert css.startswith('@import url("/static/glass.css");')


@pytest.mark.parametrize("name", [n for n in _app_pages() if n != "index.html"])   # the home page: GUI_ADDONS, tested above
def test_every_page_loads_the_layer_and_its_switch_before_first_paint(name):
    """WCAG 2.2 SC 3.2.1 (no flash of the other look) · ASVS V14.4: table over every page styled by app.css: it loads reports.css (and so glass.css) and runs glass.js in <head>."""
    html = _read(name)
    head = html[:html.index("</head>")]
    assert 'href="/static/reports.css"' in head, name
    assert '<script src="/static/glass.js"></script>' in head, name


def test_the_pages_list_is_complete():
    """ASVS V1.14.1 · negative case: the table above covers the report pages, Simple mode and the help page."""
    pages = _app_pages()
    assert len(pages) >= 30 and {"simple.html", "help.html", "report_path.html", "report_advanced.html", "report_view.html"} <= set(pages)


# ── The switch in Advanced settings ─────────────────────────────────────

def test_advanced_settings_has_the_glass_switch():
    """WCAG 2.2 SC 4.1.2, 1.3.1, 2.5.3 · ASVS V14.4: "Glass effect" is a labelled switch with a described state, on the Advanced settings page, with help on hover."""
    html = _read("report_advanced.html")
    assert '<label class="adv-switch" for="advGlass"><input type="checkbox" id="advGlass" role="switch" checked aria-describedby="advGlassNote"><span>Glass effect</span></label>' in html
    assert 'id="advGlassNote" role="status" aria-live="polite"' in html
    assert '<a class="rp-btn" href="#appearance">Appearance</a>' in html and '<section id="appearance" aria-labelledby="advLookH">' in html
    assert '"#advGlass": {' in _read("help_catalog.js")


def test_storage_is_always_wrapped_and_the_default_is_on():
    """ASVS V14.2 / CWE-248 (uncaught exception) · CISA Secure by Design (secure defaults): every localStorage access is inside try/catch, and nothing stored means on."""
    js = _read("glass.js")
    uses = [line for line in js.splitlines() if "localStorage." in line and not line.lstrip().startswith("//")]
    assert len(uses) == 2 and all("try {" in u and "catch (e)" in u for u in uses), uses
    assert "apply(read() !== 'off');" in js


NODE_HARNESS = r"""
const store = STORE; const throwing = THROWING;
const cls = new Set(); const listeners = {};
global.localStorage = { getItem(k) { if (throwing) throw new Error('blocked'); return k in store ? store[k] : null; },
                        setItem(k, v) { if (throwing) throw new Error('blocked'); store[k] = v; } };
const root = { classList: { toggle(c, on) { on ? cls.add(c) : cls.delete(c); }, contains(c) { return cls.has(c); } }, addEventListener() {} };
const docListeners = {};
global.document = { documentElement: root, readyState: 'complete', visibilityState: 'visible', getElementById: () => null, querySelectorAll: () => [], addEventListener(t, f) { docListeners[t] = f; } };
global.window = { matchMedia: q => ({ matches: false, addEventListener() {} }), addEventListener(t, f) { listeners[t] = f; }, dispatchEvent() {} };
global.CustomEvent = function (t, o) { this.type = t; this.detail = o && o.detail; };
global.requestAnimationFrame = f => 0;
SRC
const out = { first: !cls.has('glass-off') };
window.dlpGlass.set(false); out.afterOff = { off: cls.has('glass-off'), stored: throwing ? null : store.zassess_glass };
window.dlpGlass.set(true); out.afterOn = { off: cls.has('glass-off'), stored: throwing ? null : store.zassess_glass };
listeners.storage({ key: 'zassess_glass', newValue: 'off' }); out.otherTab = cls.has('glass-off');
out.stillAtStart = cls.has('glass-still');
document.visibilityState = 'hidden'; docListeners.visibilitychange(); out.stillHidden = cls.has('glass-still');
document.visibilityState = 'visible'; docListeners.visibilitychange(); out.stillShown = cls.has('glass-still');
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("store,throwing,first", [
    ({}, False, True),                                # nothing stored: on (the default)
    ({"zassess_glass": "on"}, False, True),
    ({"zassess_glass": "off"}, False, False),         # the viewer turned it off: off before the first paint
    ({"zassess_glass": "garbage"}, False, True),      # anything but "off" is on
    ({}, True, True),                                 # storage blocked (private mode): on, and no exception
])
def test_the_switch_reads_writes_and_follows_other_tabs(store, throwing, first):
    """ASVS V14.2 · CWE-248 · WCAG 2.2 SC 3.2.4, 2.2.2: the choice is read before paint, written per viewer, survives blocked storage, another tab's change is followed, and the drift pauses while the tab is hidden."""
    # Arrange
    src = NODE_HARNESS.replace("STORE", json.dumps(store)).replace("THROWING", json.dumps(throwing)).replace("SRC", _read("glass.js"))
    # Act
    out = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=10)
    # Assert
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got["first"] is first
    assert got["afterOff"] == {"off": True, "stored": None if throwing else "off"}
    assert got["afterOn"] == {"off": False, "stored": None if throwing else "on"}
    assert got["otherTab"] is True
    assert (got["stillAtStart"], got["stillHidden"], got["stillShown"]) == (False, True, False), "the drift pauses only while the tab is hidden"


# ── Contrast on the glass, against the worst case behind each tier ──────
# A colour is (r, g, b, a) with r, g, b in 0..255. color-mix(in srgb, A p, B)
# interpolates premultiplied colours, as CSS Color 5 defines it.

WHITE, BLACK, CLEAR = (255.0, 255.0, 255.0, 1.0), (0.0, 0.0, 0.0, 1.0), (0.0, 0.0, 0.0, 0.0)


def _hex(h):
    return tuple(float(int(h[i:i + 2], 16)) for i in (1, 3, 5)) + (1.0,)


def _mix(a, b, p):
    alpha = a[3] * p + b[3] * (1 - p)
    if alpha == 0:
        return CLEAR
    return tuple((a[i] * a[3] * p + b[i] * b[3] * (1 - p)) / alpha for i in range(3)) + (alpha,)


def _over(top, under):
    a = top[3]
    return tuple(top[i] * a + under[i] * (1 - a) for i in range(3)) + (1.0,)


def _lum(c):
    f = lambda x: (x / 255) / 12.92 if x / 255 <= 0.03928 else ((x / 255 + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])


def _ratio(a, b):
    x, y = sorted((_lum(a), _lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


class Theme:
    """glass.css's material for one theme, evaluated against app.css's tokens."""

    def __init__(self, theme):
        self.tokens = _tokens()[theme]
        body = _decls(_block(CSS_NO_COMMENTS, "body"))
        if theme == "light":
            body.update(_decls(_block(CSS_NO_COMMENTS, "body.theme-light")))
        self.vars = body

    def value(self, expr, depth=0):
        expr = expr.strip()
        assert depth < 12, expr
        if expr in ("white", "black", "transparent"):
            return {"white": WHITE, "black": BLACK, "transparent": CLEAR}[expr]
        m = re.fullmatch(r"var\(--([\w-]+)\)", expr)
        if m:
            name = m.group(1)
            if "--" + name in self.vars:
                return self.value(self.vars["--" + name], depth + 1)
            return _hex(self.tokens[name])
        m = re.fullmatch(r"color-mix\(in srgb,\s*(.+?)\s+(var\(--[\w-]+\)|\d+%)\s*,\s*(.+)\)", expr)
        assert m, expr
        return _mix(self.value(m.group(1), depth + 1), self.value(m.group(3), depth + 1), self.pct(m.group(2)))

    def pct(self, expr):
        m = re.fullmatch(r"var\(--([\w-]+)\)", expr)
        return float((self.vars["--" + m.group(1)] if m else expr).rstrip("%")) / 100

    def fields(self):
        """The backdrop's colour fields (--glass-amb-1, -2, ...), at their peak."""
        names = sorted((k for k in self.vars if re.fullmatch(r"--glass-amb-\d+", k)), key=lambda k: int(k.rsplit("-", 1)[1]))
        return [self.value(f"var({k})") for k in names]

    def ambient(self, bases=("bg",)):
        """Every colour the backdrop can paint: the page, each field's peak and each pair half and half (where two fields overlap)."""
        out = []
        for base in bases:
            bg = _hex(self.tokens[base])
            peaks = self.fields()
            out += [bg] + [_over(p, bg) for p in peaks]
            out += [_over(_mix(a, b, 0.5), bg) for i, a in enumerate(peaks) for b in peaks[i + 1:]]
        return out

    def worst(self, fg, tint, behind, overlays):
        """The lowest contrast of fg on tint over each backdrop, with and without each overlay (sheen, lens)."""
        lows = []
        for b in behind:
            base = _over(tint, b)
            for k in range(len(overlays) + 1):
                c = base
                for o in overlays[:k]:
                    c = _over(o, c)
                lows.append(_ratio(fg, c))
        return min(lows)


THEMES = ("dark", "light")
# (tier, its tint, what can be behind it, its overlays)
# The inner glow is counted as if it covered the whole surface (it only lights the edges): the conservative side.
TIERS = [
    ("float", "var(--glass-float-bg)", "extremes", ("var(--glass-sheen-float)", "var(--glass-glow)")),
    ("chrome", "var(--glass-chrome-bg)", "ambient", ("var(--glass-sheen-panel)", "var(--glass-glow)")),   # also the sidebar beside the page
    ("panel", "var(--glass-panel-bg)", "ambient", ("var(--glass-sheen-panel)", "var(--glass-glow)", "var(--glass-lens-on)")),
    ("capsule", "var(--glass-capsule-bg)", "ambient", ("var(--glass-sheen-panel)", "var(--glass-lens-on)")),
    ("capsule-hover", "var(--glass-capsule-hover)", "ambient", ("var(--glass-sheen-panel)", "var(--glass-lens-on)")),
    ("dense", "var(--glass-dense-bg)", "extremes", ()),
]


def _behind(t, kind):
    return [WHITE, BLACK] if kind == "extremes" else t.ambient()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("tier,tint,behind,overlays", TIERS, ids=[t[0] for t in TIERS])
def test_text_on_each_glass_tier_meets_aa_against_the_worst_backdrop(theme, tier, tint, behind, overlays):
    """WCAG 2.2 SC 1.4.3: every text token is 4.5:1 on each tier's glass, over the worst case behind it (pure white or black for floating chrome and tables; the brightest or darkest point of the page wash for surfaces in the flow), with and without the sheen and the pointer lens."""
    # Arrange
    t = Theme(theme)
    # Act
    lows = {tok: t.worst(_hex(t.tokens[tok]), t.value(tint), _behind(t, behind), [t.value(o) for o in overlays]) for tok in TEXT_TOKENS}
    # Assert
    bad = {k: round(v, 2) for k, v in lows.items() if v < 4.5}
    assert not bad, f"{theme} {tier}: {bad}"


@pytest.mark.parametrize("theme", THEMES)
def test_text_directly_on_the_page_wash_meets_aa(theme):
    """WCAG 2.2 SC 1.4.3: the soft background is low contrast: every text token is still 4.5:1 on its brightest and darkest point."""
    t = Theme(theme)
    bad = [(tok, round(_ratio(_hex(t.tokens[tok]), a), 2)) for tok in TEXT_TOKENS for a in t.ambient() if _ratio(_hex(t.tokens[tok]), a) < 4.5]
    assert not bad, bad


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("fill", ["btn", "btn-hover"])
def test_white_on_a_primary_capsule_meets_aa_over_any_parent(theme, fill):
    """WCAG 2.2 SC 1.4.3: white text on a primary button's tinted glass is 4.5:1 whatever surface it sits on (a floating bar over white or black, a panel over the wash), with its darkening sheen."""
    # Arrange
    t = Theme(theme)
    tint = _mix(_hex(t.tokens[fill]), CLEAR, t.pct("var(--glass-a-tint)"))
    parents = [_over(t.value("var(--glass-float-bg)"), b) for b in (WHITE, BLACK)]
    parents += [_over(t.value("var(--glass-panel-bg)"), a) for a in t.ambient()] + t.ambient()
    # Act
    low = t.worst(WHITE, tint, parents, [t.value("var(--glass-sheen-tint)")])
    # Assert
    assert low >= 4.5, f"{theme} {fill}: {low:.2f}"


@pytest.mark.parametrize("theme", THEMES)
def test_the_hover_help_on_glass_keeps_its_contrast(theme):
    """WCAG 2.2 SC 1.4.3, 1.4.13: the help pop-up's words (hover_help.css colours) are 4.5:1 on its glass over pure white or black."""
    # Arrange
    css = _read("hover_help.css")
    block = css.split("body.theme-light .hh-tip {", 1)[1].split("}", 1)[0] if theme == "light" else css.split(".hh-tip {", 1)[1].split("}", 1)[0]
    hh = dict(re.findall(r"--hh-([\w-]+):\s*(#[0-9a-fA-F]{6})", block))
    t = Theme(theme)
    tint = _mix(_hex(hh["bg"]), CLEAR, t.pct("var(--glass-a-float)"))
    # Act
    lows = {k: t.worst(_hex(hh[k]), tint, [WHITE, BLACK], []) for k in ("fg", "muted", "read", "write", "local")}
    # Assert
    assert min(lows.values()) >= 4.5, lows


@pytest.mark.parametrize("theme", THEMES)
def test_the_focus_ring_is_3_to_1_on_every_glass_tier(theme):
    """WCAG 2.2 SC 1.4.11, 2.4.7, 2.4.11: the 3px focus ring (--accent-hover) keeps 3:1 against every glass tier it can sit on."""
    t = Theme(theme)
    ring = _hex(t.tokens["accent-hover"])
    lows = {tier: t.worst(ring, t.value(tint), _behind(t, behind), [t.value(o) for o in overlays]) for tier, tint, behind, overlays in TIERS}
    assert min(lows.values()) >= 3, lows


@pytest.mark.parametrize("theme", THEMES)
def test_accent_text_on_its_tint_is_independent_of_the_glass(theme):
    """WCAG 2.2 SC 1.4.3: with the glass on, --accent-tint (a selected tab, a badge, a chosen card) is mixed into the opaque card, so accent and secondary text on it keep 4.5:1 whatever is behind the glass."""
    # Arrange
    head = ":root:not(.glass-off) body.theme-light" if theme == "light" else ":root:not(.glass-off) body"
    value = _decls(_block(CSS_NO_COMMENTS, head))["--accent-tint"]
    t = Theme(theme)
    # Act
    tint = t.value(value)
    # Assert
    assert tint[3] == 1.0 and "var(--card-solid)" in value, value
    for tok in ("accent", "text", "dim", "info"):
        assert _ratio(_hex(t.tokens[tok]), tint) >= 4.5, (theme, tok)


def test_the_contrast_check_fails_a_too_clear_surface():
    """WCAG 2.2 SC 1.4.3 · negative case: the same computation fails floating glass at 60% (and passes it at the shipped value), so the checks above can fail."""
    t = Theme("dark")
    tint = _mix(_hex(t.tokens["card-solid"]), CLEAR, 0.60)
    assert t.worst(_hex(t.tokens["dim"]), tint, [WHITE, BLACK], []) < 4.5
    assert t.worst(_hex(t.tokens["dim"]), t.value("var(--glass-float-bg)"), [WHITE, BLACK], []) >= 4.5


def test_the_mix_matches_css_color_5():
    """WCAG 2.2 SC 1.4.3 · CSS Color 5 color-mix(): mixing with transparent keeps the colour and scales the alpha; two opaque colours interpolate."""
    assert _mix(WHITE, CLEAR, 0.4) == (255.0, 255.0, 255.0, 0.4)
    assert _mix(WHITE, BLACK, 0.5)[:3] == (127.5, 127.5, 127.5)
    assert round(_ratio(_over((255.0, 255.0, 255.0, 0.5), BLACK), BLACK), 2) == round(_ratio((127.5, 127.5, 127.5, 1.0), BLACK), 2)


# ── The backdrop: visible, and inside the contrast budget ───────────────

@pytest.mark.parametrize("theme", THEMES)
def test_the_backdrop_has_visible_colour_fields_inside_the_contrast_budget(theme):
    """WCAG 2.2 SC 1.4.3 (the contrast budget is spent on colour the glass can show, never past it): five colour fields, each one visibly away from the page colour (12 or more on some sRGB channel), drawn on two layers; text on their brightest or darkest point is checked above and below."""
    # Arrange
    t = Theme(theme)
    bg = _hex(t.tokens["bg"])
    # Act
    fields = [_over(f, bg) for f in t.fields()]
    gaps = [max(abs(f[i] - bg[i]) for i in range(3)) for f in fields]
    # Assert
    assert len(fields) == 5 and min(gaps) >= 12, gaps
    layer = lambda pseudo: "".join(body for prelude, body in re.findall(r"([^{}]+)\{([^{}]*)\}", CSS_NO_COMMENTS) if prelude.strip().endswith(pseudo))
    assert all(f"var(--glass-amb-{i})" in layer("body:not(.has-portrait)::before") for i in (1, 2, 3))
    assert all(f"var(--glass-amb-{i})" in layer("body:not(.has-logo)::after") for i in (4, 5))


def test_the_contrast_check_fails_a_too_bright_backdrop():
    """WCAG 2.2 SC 1.4.3 · negative case: the same computation fails the dark theme's text on a colour field twice as strong (and on the shipped one passes), so the backdrop checks can fail."""
    t = Theme("dark")
    t.vars["--glass-amb-1"] = "color-mix(in srgb, var(--btn) 64%, var(--bg))"
    assert min(_ratio(_hex(t.tokens["info"]), a) for a in t.ambient()) < 4.5
    assert min(_ratio(_hex(t.tokens["info"]), a) for a in Theme("dark").ambient()) >= 4.5


# ── The extension's pages (browser_extension/glass.css) ─────────────────

EXT = os.path.join(ROOT, "browser_extension")
EXT_CSS = re.sub(r"/\*.*?\*/", "", open(os.path.join(EXT, "glass.css"), encoding="utf-8").read(), flags=re.S)
EXT_TEXT = ("text", "dim", "info", "accent", "pass", "warn", "fail")


class ExtTheme(Theme):
    """browser_extension/glass.css over browser_extension/tokens.css, for one colour scheme."""

    def __init__(self, theme):
        tokens_css = re.sub(r"/\*.*?\*/", "", open(os.path.join(EXT, "tokens.css"), encoding="utf-8").read(), flags=re.S)
        parse = lambda block: dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", block))
        dark_tokens = _block(_block(tokens_css, "@media (prefers-color-scheme: dark)"), ":root")
        self.tokens = parse(_block(tokens_css, ":root"))
        self.vars = _decls(_block(EXT_CSS, ":root"))
        if theme == "dark":
            self.tokens.update(parse(dark_tokens))
            self.vars.update(_decls(_block(_block(EXT_CSS, "@media (prefers-color-scheme: dark)"), ":root")))


EXT_TIERS = [("panel", "var(--glass-panel-bg)", ("var(--glass-sheen)",)), ("capsule", "var(--glass-capsule-bg)", ("var(--glass-sheen)",)),
             ("capsule-hover", "var(--glass-capsule-hover)", ("var(--glass-sheen)",))]


@pytest.mark.parametrize("theme", THEMES)
def test_extension_text_meets_aa_on_its_backdrop_and_glass(theme):
    """WCAG 2.2 SC 1.4.3: on the extension's pages every text colour is 4.5:1 directly on the backdrop (over the popup's card and the side panel's page colour) and on each glass surface over its worst point, with the sheen."""
    # Arrange
    t = ExtTheme(theme)
    behind = t.ambient(("card", "bg"))
    # Act
    on_wash = {k: min(_ratio(_hex(t.tokens[k]), a) for a in behind) for k in EXT_TEXT}
    on_glass = {(tier, k): t.worst(_hex(t.tokens[k]), t.value(tint), behind, [t.value(o) for o in ov]) for tier, tint, ov in EXT_TIERS for k in EXT_TEXT}
    # Assert
    assert len(t.fields()) == 3
    assert min(on_wash.values()) >= 4.5, {k: round(v, 2) for k, v in on_wash.items() if v < 4.5}
    assert min(on_glass.values()) >= 4.5, {k: round(v, 2) for k, v in on_glass.items() if v < 4.5}


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("fill", ["btn", "btn-hover"])
def test_extension_white_on_a_primary_capsule_meets_aa(theme, fill):
    """WCAG 2.2 SC 1.4.3: white text on the extension's tinted primary button is 4.5:1 over any point of the backdrop and over a glass panel, with its darkening sheen (the dark scheme's old #0a84ff fill was 3.6:1)."""
    t = ExtTheme(theme)
    tint = _mix(_hex(t.tokens[fill]), CLEAR, t.pct("var(--glass-a-tint)"))
    behind = t.ambient(("card", "bg"))
    parents = behind + [_over(t.value("var(--glass-panel-bg)"), a) for a in behind]
    assert t.worst(WHITE, tint, parents, [t.value("var(--glass-sheen-tint)")]) >= 4.5


@pytest.mark.parametrize("head", ["@media (prefers-reduced-transparency: reduce)", "@media (prefers-contrast: more)", "@media (forced-colors: active)", "@media print"])
def test_extension_fallbacks_are_solid(head):
    """WCAG 2.2 SC 1.4.3, 1.4.11 · CSS Media Queries 5: the extension's glass turns into plain, opaque surfaces and drops the backdrop for reduced transparency, more contrast, forced colours and print."""
    decls = _decls(_block(_block(EXT_CSS, head), ":root"))
    assert decls.get("--glass-solid-img") == "none"
    assert all(decls.get(a) == "100%" for a in ("--glass-a-panel", "--glass-a-capsule", "--glass-a-hover", "--glass-a-tint")), decls


def test_extension_glass_is_local_static_and_on_every_page():
    """ASVS V14.4.3 · CWE-829 · WCAG 2.2 SC 2.2.2: the extension's glass is a local stylesheet linked after each page's own (so it layers over them), with no colour literal, no remote asset, no blur and no motion; every image and shadow goes through its solid switch."""
    # Arrange
    pages = {name: open(os.path.join(EXT, name), encoding="utf-8").read() for name in ("popup.html", "panel.html", "options.html")}
    # Act
    decls = re.findall(r"(?<![\w-])(background-image|box-shadow)\s*:\s*([^;]+);", EXT_CSS)
    # Assert
    for name, own in (("popup.html", "popup.css"), ("panel.html", "panel.css"), ("options.html", "options.css")):
        html = pages[name]
        assert html.index(f'href="{own}"') < html.index('<link rel="stylesheet" href="glass.css">') < html.index("</head>"), name
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|url\(|https?:", EXT_CSS)
    assert not re.search(r"backdrop-filter|animation|transition|@keyframes", EXT_CSS)
    assert len(decls) >= 5 and all(v.startswith(("var(--glass-solid-img,", "var(--glass-solid-shadow,")) for _, v in decls), decls


# ── What the glass costs to draw (measured: tests/test_glass_perf_browser.py) ──

def test_the_drift_steps_about_once_a_second_on_both_layers_together():
    """CWE-400 · CWE-1050 · performance: each drift step draws every blurred layer again, so each backdrop layer steps at most once a second, and both at the same moments (the same seconds per step), never four or more times a second as before.
    An animation's timing function applies to each keyframe interval, not to the whole run: steps(n) over k intervals is k * n steps."""
    # Arrange
    drift = float(_decls(_block(CSS_NO_COMMENTS, "body"))["--glass-drift"].rstrip("s"))
    uses = re.findall(r"(?<![\w-])animation\s*:\s*var\(--glass-solid-motion, (glass-drift-\w+) (var\(--glass-drift\)|calc\(var\(--glass-drift\) \* ([\d.]+)\)) steps\((\d+)\)", CSS_NO_COMMENTS)
    intervals = {name: len(re.findall(r"[\d.]+%\s*\{", _block(CSS_NO_COMMENTS, "@keyframes " + name))) - 1 for name, *_ in uses}
    # Act
    per_step = [drift * (float(scale) if scale else 1.0) / (intervals[name] * int(n)) for name, _dur, scale, n in uses]
    # Assert
    assert len(per_step) == 2 and all(s >= 1.0 for s in per_step), per_step
    assert abs(per_step[0] - per_step[1]) < 1e-9, per_step


def test_while_the_page_scrolls_the_in_flow_glass_drops_its_blur_and_the_drift_holds():
    """CWE-400 · CWE-1050 · WCAG 2.2 SC 2.2.2: glass.js sets html.glass-scrolling from one passive capturing scroll listener (cleared after the scroll ends, nothing per frame); glass.css then drops the blur of the cards and the tier 2 chrome in the page flow (the same selectors that blur them) and holds the drift, while the floating tier keeps its blur."""
    # Arrange
    js = _read("glass.js")
    rule = re.search(r":root:not\(\.glass-off\)\.glass-scrolling :is\(\.rp-card[^{]+\{([^{}]*)\}", CSS_NO_COMMENTS)
    # Act
    selectors = rule.group(0).split("{")[0] if rule else ""
    # Assert
    assert "document.addEventListener('scroll', scrolled, { passive: true, capture: true });" in js
    assert "root.classList.remove('glass-scrolling')" in js and "requestAnimationFrame(scrolled" not in js
    assert rule and "backdrop-filter: none" in rule.group(1), rule
    assert ".glass-fit" in selectors and ".rp-hero" in selectors and "#stepBar" in selectors
    assert not re.search(r"\.rp-bar|#dbSidebar|dialog|\.hh-tip", selectors), selectors
    body = _block(CSS_NO_COMMENTS, ":root:not(.glass-off).glass-scrolling body::before,\n:root:not(.glass-off).glass-scrolling body::after")
    assert "animation-play-state: paused" in body


def test_while_the_page_scrolls_the_page_bar_drops_its_blur_and_the_small_floating_glass_keeps_it():
    """CWE-400 · CWE-1050 · WCAG 2.2 SC 1.4.3: the page bar (floating, as wide as the page, 95% opaque) drops its backdrop blur while html.glass-scrolling is set, so a scrolled frame does not read its backdrop back each frame; the theme button and the help pop-up keep theirs."""
    # Arrange
    rp_bar = dict((k.strip(), v.strip()) for k, v in re.findall(r"([\w-]+)\s*:\s*([^;]+);", _block(CSS_NO_COMMENTS, ":root:not(.glass-off).glass-scrolling .rp-bar")))
    # Act
    scrolling_heads = re.findall(r"([^{}]*glass-scrolling[^{}]*)\{", CSS_NO_COMMENTS)
    # Assert
    assert rp_bar["backdrop-filter"] == "none !important" and rp_bar["-webkit-backdrop-filter"] == "none !important", rp_bar
    assert not any(re.search(r"themeToggleBtn|\.hh-tip|#dbSidebar|dialog", h) for h in scrolling_heads), scrolling_heads


def test_the_drift_only_translates_its_layers_so_a_scrolled_frame_never_resamples_them():
    """CWE-400 · CWE-1050: the backdrop drift's keyframes are translations only (no rotate or scale), so its two page-sized layers, drawn on every scrolled frame, are never resampled; the drift still moves both layers."""
    # Arrange
    frames = dict(re.findall(r"@keyframes\s+(glass-drift-\w+)\s*\{((?:[^{}]*\{[^{}]*\})*)\s*\}", CSS_NO_COMMENTS))
    # Act
    values = {name: re.findall(r"transform\s*:\s*([^;}]+)", body) for name, body in frames.items()}
    # Assert
    assert set(values) == {"glass-drift-a", "glass-drift-b"}, values
    for name, vs in values.items():
        assert vs and all(re.fullmatch(r"translate3d\([^()]*\)", v.strip()) for v in vs), (name, vs)
        assert len({v.strip() for v in vs}) > 1, (name, vs)
