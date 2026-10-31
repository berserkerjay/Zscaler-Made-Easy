"""The plain-English layer: every function on the toolbar has an entry in
the explain catalogue, every report page loads the explainer box, and
the /help page lists every function, the glossary and the trouble list."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


# Toolbar opener -> catalogue key. A new toolbar button must be added here
# AND to explain.js, so nothing ships unexplained.
TOOLBAR = {
    "openHelpTab()": "help", "openDataFlowTab()": "dataflow", "openPathAnalyzerTab()": "path", "openFlowAnimatorTab()": "motion", "openShadowRulesTab()": "shadow",
    "openHelpTab()": "help", "openDataFlowTab()": "dataflow", "openPathAnalyzerTab()": "path", "openFlowAnimatorTab()": "motion", "openZpaTab()": "zpa", "openDevicePostureTab()": "deviceposture",
    "openHelpTab()": "help", "openDataFlowTab()": "dataflow", "openPathAnalyzerTab()": "path", "openFlowAnimatorTab()": "motion", "openZpaTab()": "zpa",
    "openBrowserSecurityTab()": "browser",
    "openHelpTab()": "help", "openDataFlowTab()": "dataflow", "openPathAnalyzerTab()": "path", "openFlowAnimatorTab()": "motion", "openSimpleMode()": "simple",
    "openToolTab('efficacy')": "efficacy", "openDetectionHealthTab()": "health", "openDlpPacksModal()": "packs",
    "openToolTab('terraform')": "terraform", "openVendorMigrateTab()": "vendormigrate", "_gdGoMigration()": "migration", "openEvalAllTab()": "evalall", "openOperationsTab()": "operations",
    "openToolTab('bestpractices')": "bestpractices", "openAdvancedTab()": "advanced", "openToolTab('updates')": "updates",
    "openLogAnalyzerTab()": "logs", "openTrafficLogsTab()": "trafficlogs", "openBeaconTab()": "beacon", "openDigestTab()": "digest", "openLiveFeedTab()": "live", "openInsightsTab()": "insights", "openAuditTimelineTab()": "audit", "openSslCoverageTab()": "sslcoverage",
    "openToolTab('bestpractices')": "bestpractices", "openAdvancedTab()": "advanced", "openToolTab('updates')": "updates", "openExportsTab()": "exports",
    "openToolTab('bestpractices')": "bestpractices", "openAdvancedTab()": "advanced", "openToolTab('updates')": "updates", "openQueueTab()": "queue",
    "openSelfHealTab()": "selfheal",
    "openLogAnalyzerTab()": "logs", "openBeaconTab()": "beacon", "openDigestTab()": "digest", "openLiveFeedTab()": "live",
    "openLogAnalyzerTab()": "logs", "openBeaconTab()": "beacon", "openDigestTab()": "digest", "openLiveFeedTab()": "live", "openFleetTab()": "fleet",
    "openReferenceTab('data-security-portfolio-framework')": "refportfolio", "openReferenceTab('ai-security-framework')": "refai",
    "openReferenceTab('genai-security-framework')": "refgenai", "openReferenceTab('framework-machine')": "refmachine",
    "openReferenceTab('data-security-architect')": "dsarchitect",
    "openPostureTab()": "posture",
    "openFindAnything()": "find", "openTodoTab()": "todo", "openPovTab()": "pov",
}


def _catalogue_keys():
    js = _read("explain.js")
    return set(re.findall(r"^\s{2}X\.(\w+) = \{", js, re.M))


def test_every_toolbar_button_is_explained():
    html = _read("index.html")
    start = html.index('<div class="hero-toolbar"')
    end = html.index("<!-- DLP efficacy modal -->", start)
    toolbar = html[start:end]
    clicks = re.findall(r'onclick="([^"]+)"', toolbar)
    assert clicks, "toolbar has buttons"
    unknown = [c for c in clicks if c not in TOOLBAR]
    assert not unknown, f"toolbar buttons without an explanation: {unknown}"
    keys = _catalogue_keys()
    missing = [k for k in TOOLBAR.values() if k not in keys]
    assert not missing, f"explain.js lacks: {missing}"
    assert 'aria-label="Troubleshoot"' in toolbar and "Log analyzer" in toolbar
    assert "What does everything do?" in toolbar


def test_catalogue_entries_are_complete_sentences_for_a_first_week_engineer():
    js = _read("explain.js")
    for key in _catalogue_keys():
        block = js[js.index(f"  X.{key} = {{"):]
        block = block[: block.index("\n  };")]
        for field in ("group", "name", "what", "why", "when", "get", "next"):
            m = re.search(rf"(?:^|[\s,])\s*{field}: '((?:[^'\\]|\\.)*)'", block, re.M)
            assert m, f"{key} lacks {field}"
            if field not in ("group", "name"):
                assert len(m.group(1)) >= 40, f"{key}.{field} is too short to help anyone"
    groups = set(re.findall(r"group: '([^']+)'", js))
    assert groups == {"Start", "Find the gaps", "Close the gaps", "Reference", "Troubleshoot"}


def test_every_report_route_has_an_explainer_and_loads_the_script():
    js = _read("explain.js")
    routes = sorted(r.path for r in srv.app.routes if getattr(r, "path", "").startswith("/report/"))
    for path in routes:
        assert f"'{path}'" in js, f"explain.js does not map {path}"
    for name in sorted(n for n in os.listdir(STATIC) if n.startswith("report_") and n.endswith(".html")) + ["help.html"]:
        html = _read(name)
        assert '<script src="/static/explain.js"></script>' in html, name
        assert '<script src="/static/report_theme.js"></script>' in html, name
        assert html.index("report_theme.js") < html.index("explain.js"), name
    assert "hero.insertAdjacentElement('afterend', box)" in js and "zassess_explain_hidden" in js


def test_help_page_and_guide_share_one_catalogue():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    page = c.get("/help")
    assert page.status_code == 200
    for needle in ("DLP_FIRST_DAY", "DLP_EXPLAIN_CARD", "DLP_GLOSSARY", "DLP_TROUBLE", 'id="glossary"', 'id="trouble"', "<main"):
        assert needle in page.text, needle
    guide = _read("guide.js")
    assert "const GD_GLOSSARY = window.DLP_GLOSSARY" in guide and "window.DLP_TROUBLE" in guide
    assert 'href="/help"' in guide and "<dt>Log analyzer</dt>" in guide
    home = c.get("/").text
    assert home.index("/static/explain.js") < home.index("/static/guide.js")
    js = _read("explain.js")
    for term in ("Client Connector (ZCC)", "PAC file", "Captive portal", "Z-Tunnel 1.0 / 2.0"):
        assert term in js


def test_every_page_has_its_own_explainer_entry():
    """WCAG 2.2 SC 3.3.2, 2.4.6 · each page's explainer is its own: no catalogue key is defined twice (a second X.posture
    replaced Device posture with Improve my score), and every mapped path opens the entry whose href is that path."""
    js = _read("explain.js")
    keys = re.findall(r"^\s{2}X\.(\w+) = \{", js, re.M)
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    assert not dupes, f"explain.js defines these keys twice: {dupes}"
    mapping = dict(re.findall(r"'(/[^']*)': '(\w+)'", js.split("function keyFor", 1)[1].split("return map[p]", 1)[0]))
    assert mapping, "keyFor has a path map"
    for path, key in mapping.items():
        block = js[js.index(f"  X.{key} = {{"):]
        href = re.search(r"href: '([^']*)'", block[: block.index("\n  };")])
        if href and href.group(1).startswith("/report/"):
            assert href.group(1) == path, f"{path} opens X.{key}, whose href is {href.group(1)}"
    order = re.search(r"DLP_EXPLAIN_ORDER = \[([^\]]+)\]", js).group(1)
    assert "'deviceposture'" in order and "'posture'" in order


# ── Wave 6 UI check: the help text matches the app (WCAG 2.2 AA) ────────
# The catalogue is read by running explain.js itself in node (no regex over
# the source), so what is checked is exactly what the pages render.
import json
import shutil
import subprocess

import pytest

_CATALOGUE_JS = r"""
global.window = { location: { pathname: '/x', search: '' } };
global.document = { body: null, addEventListener() {} };
global.localStorage = { getItem() { return null; }, setItem() {} };
require(process.argv[1]);
const X = window.DLP_EXPLAIN, map = {};
for (const p of PATHS) map[p] = window.DLP_EXPLAIN_KEY({ pathname: p, search: '' });
process.stdout.write(JSON.stringify({ keys: Object.keys(X), order: window.DLP_EXPLAIN_ORDER, groups: window.DLP_EXPLAIN_GROUPS,
  hrefs: Object.fromEntries(Object.entries(X).map(([k, x]) => [k, x.href])), map, first: window.DLP_FIRST_DAY.map(r => r[1]) }));
"""


def _page_paths():
    return sorted({r.path for r in srv.app.routes if getattr(r, "methods", None) and "GET" in r.methods and "{" not in r.path
                   and (r.path.startswith("/report/") or r.path in ("/", "/help", "/simple", "/permissions"))})


@pytest.fixture(scope="module")
def catalogue():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    js = _CATALOGUE_JS.replace("PATHS", json.dumps(_page_paths()))
    out = subprocess.run([node, "-e", js, os.path.join(STATIC, "explain.js")], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _catalogue_keys_static():
    return sorted(set(re.findall(r"^\s{2}X\.(\w+) = \{", _read("explain.js"), re.M)))


@pytest.mark.parametrize("key", _catalogue_keys_static())
def test_every_catalogue_entry_has_its_card_on_the_help_page(catalogue, key):
    """WCAG 2.2 SC 2.4.4, 2.4.5 · /help draws only DLP_EXPLAIN_ORDER: every entry is in it, so "Every function explained" (/help#<key>) never lands on a missing card."""
    assert key in catalogue["order"], f"X.{key} is not in DLP_EXPLAIN_ORDER, so /help#{key} has no card"


def test_the_help_order_names_only_real_entries_once(catalogue):
    """WCAG 2.2 SC 2.4.5 · negative case: the order lists no unknown key and no key twice."""
    order = catalogue["order"]
    assert len(order) == len(set(order)), [k for k in order if order.count(k) > 1]
    assert set(order) <= set(catalogue["keys"]), sorted(set(order) - set(catalogue["keys"]))
    assert set(catalogue["first"]) <= set(order), "the first-day list links to cards that exist"


@pytest.mark.parametrize("path", _page_paths())
def test_every_page_opens_its_own_explainer_and_its_help_card(catalogue, path):
    """WCAG 2.2 SC 2.4.4, 3.3.2 · table over every page route: the explainer key is a catalogue entry whose card is on /help, and its href is the page itself."""
    key = catalogue["map"][path]
    if path in ("/", "/help", "/simple"):
        assert key in ("assessment", "help", "simple"), (path, key)
        return
    assert key, f"{path} has no explainer (keyFor)"
    assert key in catalogue["order"], f"{path} -> X.{key} has no card on /help"
    assert catalogue["hrefs"][key].split("?")[0] == path, (path, key, catalogue["hrefs"][key])


def _internal_links():
    """Every literal same-app link in the interface: href="/...", href: '/...', open('/...'), with the template part cut off."""
    found = set()
    for name in sorted(os.listdir(STATIC)):
        if not name.endswith((".html", ".js")):
            continue
        for m in re.finditer(r"""(?:href=|href:\s?|open\(|location\.href\s?=\s?)["'`](/[A-Za-z0-9_./-]*)(?![A-Za-z0-9_./-]*\$\{)([?#][^"'`\s$]*)?""", _read(name)):
            found.add((m.group(1), (m.group(2) or "")))
    return sorted(found)


@pytest.mark.parametrize("path,suffix", _internal_links())
def test_no_internal_link_is_dead(path, suffix):
    """WCAG 2.2 SC 2.4.4 · CWE-1059: table over every literal internal link in static/: the page or file answers 200, and a /help#anchor names a card that exists."""
    if path.startswith("/api/") and not suffix:
        r = TestClient(srv.app).get(path)
        assert r.status_code < 500, (path, r.status_code)
        return
    if path.startswith("/api/"):
        pytest.skip("an API link with a run-time id")
    r = TestClient(srv.app).get(path)
    assert r.status_code == 200, (path, r.status_code)
    if path == "/help" and suffix.startswith("#") and len(suffix) > 1:
        anchor = suffix[1:]
        assert anchor in ("glossary", "trouble") or anchor in _catalogue_keys_static(), suffix
        if anchor in _catalogue_keys_static():
            order = re.search(r"DLP_EXPLAIN_ORDER = \[([^\]]+)\]", _read("explain.js")).group(1)
            assert f"'{anchor}'" in order, f"/help#{anchor} has no card"


def _build_hand_offs():
    """Every literal /report/operations?build=<type> in the interface and in the findings (Python)."""
    found = set()
    for folder, ext in ((STATIC, (".html", ".js")), (ROOT, (".py",))):
        for name in sorted(os.listdir(folder)):
            if name.endswith(ext):
                text = open(os.path.join(folder, name), encoding="utf-8").read()
                found |= set(re.findall(r"/report/operations\?build=([a-z][a-z0-9_]{1,40})\b", text))
    return sorted(found)


@pytest.mark.parametrize("build", _build_hand_offs())
def test_every_build_hand_off_names_a_registered_builder(build):
    """WCAG 2.2 SC 2.4.4, 3.2.4 · table over every ?build= link: it names a builder the Bulk changes page registers (or the documented ZPA alias), so the link opens that builder."""
    types = {p["type"] for p in TestClient(srv.app).get("/api/operations/plugins").json()["plugins"]}
    assert len(types) >= 10, types   # the catalogue was really read
    if build == "zpa":   # the ZPA page's link opens the first ZPA builder (ops_zpa.js)
        assert "want === 'zpa' ? 'zpa_connector_group'" in _read("ops_zpa.js") and "zpa_connector_group" in types
    else:
        assert build in types, f"?build={build} names no registered builder"


def _builder_labels():
    return sorted(p["label"] for p in TestClient(srv.app).get("/api/operations/plugins").json()["plugins"])


@pytest.mark.parametrize("label", _builder_labels())
def test_the_bulk_changes_explainer_names_every_builder(label):
    """WCAG 2.2 SC 3.3.2 · CWE-1059: table over every builder Bulk changes registers: its explainer (the page box, /help and Find anything) names it (none of the thirteen builders was mentioned)."""
    js = _read("explain.js")
    block = js[js.index("  X.operations = {"):]
    block = block[: block.index("\n  };")].lower()
    assert label.lower() in block, f"X.operations does not mention the builder {label!r}"


@pytest.mark.parametrize("key,phrases", [
    ("fleet", ["install command", "service health by client connector version", "last seen", "sites", "history",
               "csv exports", "pdf report"]),                                          # report_fleet.html sections (2026-10-31 too)
    ("advanced", ["secure by design", "upstream contract check", "app updates"]),    # report_advanced.html sections
    ("live", ["forwarding profiles", "pac files"]),                                  # report_live.html inventory
    ("pov", ["runbook", "test kit", "report"]),                                      # report_pov.html tabs
    ("path", ["what-if", "har", "list"]),                                            # report_path.html views
    ("trafficlogs", ["sessions", "failure reason", "health", "anomalies", "rules hit", "dlp", "ssl", "siem"]),   # report_traffic_logs.html sections
    ("connect", ["sample tenant", "snapshot", "readiness"]),                         # Connect page (Wave 5)
])
def test_every_page_explainer_names_the_sections_the_page_has(key, phrases):
    """WCAG 2.2 SC 3.3.2 · CWE-1059: table over pages: the explainer (page box, /help, Find anything) names each section the page shows (fleet's install command builder and three Advanced settings sections were missing)."""
    js = _read("explain.js")
    block = js[js.index(f"  X.{key} = {{"):]
    block = block[: block.index("\n  };")].lower()
    assert [p for p in phrases if p not in block] == []
