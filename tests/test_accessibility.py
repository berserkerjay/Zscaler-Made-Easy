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
