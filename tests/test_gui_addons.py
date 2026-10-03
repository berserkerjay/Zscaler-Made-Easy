"""
The served GUI is index.html plus server-injected add-on tags. index.html's
inline script contains template literals that build OTHER html documents,
so "</head>" and "</body>" occur inside the JavaScript too. These tests pin
the injection to the document's real closing tags and prove the inline
script survives untouched (and still parses, when node is available).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "static", "index.html")

_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_SRC_SCRIPT = re.compile(r'<script[^>]*\bsrc="([^"]+)"')


def test_injection_ignores_closing_tags_inside_scripts():
    html = (
        "<html><head><title>t</title></head><body>\n"
        "<script>\nconst page = `<html><head></head><body>x</body></html>`;\n"
        "function f() { return page; }\n</script>\n"
        "</body></html>"
    )
    out = srv._inject_gui_addons(html)
    # The inline script must be byte-identical after injection.
    assert _INLINE_SCRIPT.findall(out) == _INLINE_SCRIPT.findall(html)
    # Add-on tags land at the document's real head/body, not inside the JS.
    link_at = out.find('<link rel="stylesheet" href="/static/deploy_studio.css?v=')
    script_at = out.find('<script src="/static/deploy_studio.js?v=')
    assert 0 < link_at < out.find("<body>")
    # After the inline script's closing tag, before the document's last </body>.
    assert out.find("</script>") < script_at < out.rfind("</body>")


def test_real_index_html_survives_injection():
    html = open(INDEX, encoding="utf-8").read()
    out = srv._inject_gui_addons(html)
    assert _INLINE_SCRIPT.findall(out) == _INLINE_SCRIPT.findall(html), "inline script altered by injection"
    srcs = [x.split("?")[0] for x in _SRC_SCRIPT.findall(out)]
    # index.html loads the app-wide safety banner itself (every page does, see test_safety_banner.py); the rest are add-ons.
    assert srcs == ["/static/safety_banner.js", "/static/icons.js", "/static/ui_auth.js", "/static/rate_gate.js", "/static/deploy_studio.js", "/static/explain.js", "/static/guide.js", "/static/update_beacon.js", "/static/eval_all.js", "/static/bypass_report.js", "/static/tool_tabs.js", "/static/sidebar_order.js", "/static/dashboard.js"], srcs
    assert all("?v=" in x for x in _SRC_SCRIPT.findall(out) if "safety_banner.js" not in x)   # add-ons are cache-busted (every /static file is revalidated anyway)
    assert out.count("</body>") == html.count("</body>")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_served_inline_script_parses(tmp_path):
    html = srv._inject_gui_addons(open(INDEX, encoding="utf-8").read())
    for i, body in enumerate(_INLINE_SCRIPT.findall(html)):
        p = tmp_path / f"inline_{i}.js"
        p.write_text(body, encoding="utf-8")
        r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-800:]
