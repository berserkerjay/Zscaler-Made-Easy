"""The glass effect (static/glass.css, static/glass.js): one shared material,
its solid fallbacks, its wiring on every page, and the WCAG 2.2 AA contrast of
text on it, computed against the worst case behind each tier.

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
    assert len(ALPHAS) >= 5 and all(decls.get(a) == "100%" for a in ALPHAS), (head, {a: decls.get(a) for a in ALPHAS})
    assert re.search(r"body, body\.theme-light, body\.has-portrait, body\.has-logo\s*\{", body), "covers both themes and the branding override"


@pytest.mark.parametrize("head", ["@media print", "@media (forced-colors: active)", "@media (prefers-contrast: more)"])
def test_print_contrast_and_forced_colours_also_drop_the_shadows(head):
    """WCAG 2.2 SC 1.4.11 · SC 1.4.3: plain surfaces for print, more contrast and forced colours: no drop shadow, no rim."""
    assert _decls(_block(CSS_NO_COMMENTS, head)).get("--glass-solid-shadow") == "none"


def test_reduced_motion_turns_the_pointer_lens_off_and_nothing_shimmers():
    """WCAG 2.2 SC 2.3.3 · SC 2.2.2: under prefers-reduced-motion the pointer-follow highlight is transparent; the material has no animation or transition at all."""
    body = _block(CSS_NO_COMMENTS, "@media (prefers-reduced-motion: reduce)")
    assert _decls(body).get("--glass-lens-on") == "transparent"
    assert not re.search(r"\b(animation|transition|@keyframes)\b", CSS_NO_COMMENTS)
    js = _read("glass.js")
    assert "'(prefers-reduced-motion: reduce)'" in js and "requestAnimationFrame(draw)" in js


def test_every_blur_sheen_and_shadow_goes_through_its_solid_switch():
    """WCAG 2.2 SC 1.4.3 · CSS Media Queries 5: every backdrop-filter, background-image and box-shadow of the material can be switched off by the fallbacks (no rule bypasses them)."""
    # Arrange
    rules = re.sub(r"@supports[^{]*\{", "{", CSS_NO_COMMENTS)   # the feature test itself is not a declaration
    decls = re.findall(r"(?<![\w-])(-webkit-backdrop-filter|backdrop-filter|background-image|box-shadow)\s*:\s*([^;]+);", rules)
    switch = {"-webkit-backdrop-filter": "var(--glass-solid-filter,", "backdrop-filter": "var(--glass-solid-filter,",
              "background-image": "var(--glass-solid-img,", "box-shadow": "var(--glass-solid-shadow,"}
    # Act
    bad = [(p, v[:60]) for p, v in decls if not v.startswith(switch[p]) and v != "none"]   # "none" only ever takes glass away
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
    rules = [p for p in preludes if not p.startswith(("@property", "@media", "@supports"))
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
global.document = { documentElement: root, readyState: 'complete', getElementById: () => null, addEventListener() {} };
global.window = { matchMedia: q => ({ matches: false, addEventListener() {} }), addEventListener(t, f) { listeners[t] = f; }, dispatchEvent() {} };
global.CustomEvent = function (t, o) { this.type = t; this.detail = o && o.detail; };
global.requestAnimationFrame = f => 0;
SRC
const out = { first: !cls.has('glass-off') };
window.dlpGlass.set(false); out.afterOff = { off: cls.has('glass-off'), stored: throwing ? null : store.zassess_glass };
window.dlpGlass.set(true); out.afterOn = { off: cls.has('glass-off'), stored: throwing ? null : store.zassess_glass };
listeners.storage({ key: 'zassess_glass', newValue: 'off' }); out.otherTab = cls.has('glass-off');
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
    """ASVS V14.2 · CWE-248 · WCAG 2.2 SC 3.2.4: the choice is read before paint, written per viewer, survives blocked storage, and another tab's change is followed."""
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

    def ambient(self):
        """Every colour the page wash can paint: the page, each blob's peak and each pair half and half."""
        bg = _hex(self.tokens["bg"])
        peaks = [self.value(f"var(--glass-amb-{i})") for i in (1, 2, 3)]
        out = [bg] + [_over(p, bg) for p in peaks]
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
TIERS = [
    ("float", "var(--glass-float-bg)", "extremes", ("var(--glass-sheen-float)",)),
    ("chrome", "var(--glass-chrome-bg)", "ambient", ("var(--glass-sheen-panel)",)),
    ("panel", "var(--glass-panel-bg)", "ambient", ("var(--glass-sheen-panel)", "var(--glass-lens-on)")),
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
