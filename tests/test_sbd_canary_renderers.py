"""ASVS V5.3.1 · ASVS V5.3.3 · CWE-79 · CWE-1236 · CWE-74 · OWASP A03:2021 · WSTG-INPV-11: canary names through the sample tenant and every renderer.

Every name, configured name, display name and description of the sample
tenant is given one of five canaries before it is opened as an (untrusted)
snapshot: markup with an event handler, a Terraform/JNDI template, a
spreadsheet formula, a path traversal and a right-to-left override with a
zero-width space. The tenant label carries markup and ../ too. The tenant
reading jobs run on it (Path analyzer, shadowed rules, ZPA, SSL coverage,
browser security, device posture, Client Connector fleet, Test a list, HAR
batch, policy, location, Client Connector and URL exports, Export from
tenant, Terraform with a hostile assessor name), then every export of each
is fetched in every format it answers and checked by kind:

* HTML: no raw canary markup;
* Markdown: rendered as a viewer does (CommonMark, raw HTML on) gives no tag;
* CSV and Excel: no cell starts a formula, Excel has no formula element;
* Terraform: strict HCL with no live template sequence of the data's own;
* Word and Excel: well-formed XML; JSON: valid JSON (no NaN);
* every file name (download and archive member): no path, no markup;
* no explicit bidirectional control survives outside JSON.

No network (offline tenant), stores in a temporary folder; the jobs run once
for the module (their threads are joined: no sleep, no poll).
"""
from __future__ import annotations

import csv
import html as htmllib
import io
import json
import os
import re
import xml.dom.minidom
import zipfile

import pytest
from fastapi.testclient import TestClient

import hcl_strict
import offline_tenant as ot
import sample_tenant

CANARIES = ["<img src=x onerror=alert(1)>", "${jndi:ldap://x}%{if 1}", "=cmd|' /C calc'!A0", "../../etc/passwd", "\u202eexe.txt\u200b"]
NAME_KEYS = {"name", "configuredName", "description", "displayName"}
SCOPE = {"scopes": ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"],
         "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                             "ssl_inspection", "cloud_app_control")}, "from_page": True}
JOBS = {
    "path": ("/api/path-analyzer/start", {"destination": "chat.openai.com"}),
    "shadow": ("/api/shadow-rules/start", {}),
    "zpa": ("/api/zpa/analysis/start", {}),
    "ssl": ("/api/ssl-coverage/start", {}),
    "browser": ("/api/browser-security/start", {}),
    "posture": ("/api/device-posture/start", {}),
    "fleet": ("/api/zcc/fleet/start", {}),
    "list": ("/api/bulk-test/start", {"text": "destination,label\nchat.openai.com,=cmd|' /C calc'!A0\n10.0.0.1,<img src=x onerror=alert(4)>",
                                      "lookup": False}),
    "har": ("/api/path-analyzer/batch/start", {"har_hosts": ["chat.openai.com", "example.com"]}),
    "policies_xlsx": ("/api/exports/policies/start", {"format": "xlsx"}),
    "policies_pdf": ("/api/exports/policies/start", {"format": "pdf"}),
    "locations": ("/api/exports/locations/start", {"format": "xlsx"}),
    "zcc_export": ("/api/exports/client-connector/start", {"format": "xlsx"}),
    "urls": ("/api/exports/urls/start", {"format": "xlsx"}),
    "pack": ("/api/dlp-packs/export/start", {"pack_name": "<img src=x onerror=alert(3)>${x}"}),
    "terraform": ("/api/dlp-packs/terraform/start", {"pack_ids": ["cjis_policy_pack"], "assessor": "Eve ${x} %{y} <img src=x onerror=1> \u202e"}),
}
# (export id, URL template filled from the job ids and results)
EXPORTS = [
    ("data flow", "/api/report/data-flow/export/{path[report_id]}"),
    ("ZPA", "/api/zpa/report/{zpa[report_id]}/export"),
    ("SSL coverage", "/api/ssl-coverage/export/{ssl[report_id]}"),
    ("browser security", "/api/browser-security/report/{browser[report_id]}/export"),
    ("device posture", "/api/device-posture/report/{posture[report_id]}/export"),
    ("shadowed rules", "/api/shadow-rules/jobs/{shadow[job]}/export"),
    ("fleet plan", "/api/zcc/fleet/{fleet[job]}/export?what=plan"),
    ("fleet devices", "/api/zcc/fleet/{fleet[job]}/export?what=devices"),
    ("Test a list", "/api/bulk-test/{list[job]}/export?rows=all"),
    ("HAR batch", "/api/path-analyzer/batch/{har[job]}/export"),
] + [(f"{k} download", f"/api/dlp-packs/jobs/{{{k}[job]}}/download")
     for k in ("policies_xlsx", "policies_pdf", "locations", "zcc_export", "urls", "pack", "terraform")]
FORMATS = ("csv", "xlsx", "pdf", "docx", "json", "markdown", "html", "zip")
TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
NUMBER = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


def _canary(v, key="", n=[0]):  # noqa: B006 — a counter shared by the walk
    if isinstance(v, dict):
        return {k: _canary(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [_canary(x, key) for x in v]
    if isinstance(v, str) and key in NAME_KEYS:
        n[0] += 1
        c = CANARIES[n[0] % len(CANARIES)]
        return f"{c}{n[0]} {v}" if c.startswith("=") else f"{c} {v}"
    return v


def _reset_rate_limit(app):
    import security
    layer = getattr(app, "middleware_stack", None)
    while layer is not None:
        if isinstance(layer, security.RateLimitMiddleware):
            layer.buckets.clear()
            return
        layer = getattr(layer, "app", None)


@pytest.fixture(scope="module")
def canary_run(tmp_path_factory):
    """The canary tenant opened as a snapshot, every job run on it once (threads joined)."""
    import dlp_api_server as srv
    import pack_jobs
    tmp = tmp_path_factory.mktemp("canary")
    with pytest.MonkeyPatch.context() as mp:
        for var, name in (("DLP_CHECK_PROFILES", "profiles/p.json"), ("DLP_CHECK_DEPLOYMENTS", "d.json"), ("DLP_CHECK_AUDIT", "a.log"),
                          ("DLPCHECK_PROPOSALS_FILE", "pr.json"), ("DLP_CHECK_FINGERPRINT_KEY", "fp.key")):
            mp.setenv(var, str(tmp / name))
        mp.setenv("DLP_CHECK_SECRET_STORE", "file")
        import pack_ops
        import zia_rate
        mp.setattr(pack_ops, "_sleep", lambda s: None)   # as conftest's _no_backoff_sleep, for this module-wide run
        for bucket in zia_rate.DEFAULTS:
            mp.setenv(f"DLP_CHECK_ZIA_LIMIT_{bucket.upper()}", "off")
        mp.setattr(zia_rate, "_covers", lambda bucket: True)
        mp.setattr(zia_rate, "_sleep", lambda s: None)
        zia_rate.reset()
        import workload_path
        import zpa_reader
        mp.setattr(zpa_reader, "PACE_SECONDS", 0)   # the offline tenant has no rate limit to keep under
        mp.setattr(workload_path, "PACE_SECONDS", 0)
        for k in list(os.environ):
            if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
                mp.delenv(k, raising=False)
        mp.setattr(ot, "_OPEN", type(ot._OPEN)())
        mp.setattr(srv, "_REPORTS", {})
        client = TestClient(srv.app, base_url="http://127.0.0.1", raise_server_exceptions=False)
        resp = {ot.normalize_path(p): {"status": 200, "body": _canary(b)} for p, b in sample_tenant.responses().items()}
        doc = {"format": ot.FORMAT, "version": ot.VERSION, "meta": {"tenant_label": "<img src=x onerror=alert(2)> ../x \u202e"}, "responses": resp}
        opened = client.post("/api/tenant-profiles/snapshots/open-file", json={"name": "../c.json", "content": json.dumps(doc)})
        assert opened.status_code == 200, opened.text
        runs = {}
        for key, (path, body) in JOBS.items():
            _reset_rate_limit(srv.app)
            r = client.post(path, json=dict(SCOPE, **body))
            assert r.status_code == 200, (key, r.text[:300])
            job = pack_jobs.get(r.json()["job_id"])
            job.thread.join(120)
            assert job.status == pack_jobs.DONE, (key, job.status, job.error)
            runs[key] = dict(job.result or {}, job=job.id)
        yield client, srv.app, runs


def _check_name(name, where, problems):
    if not name:
        return
    if any(x in name for x in ("/", "\\", "..", "\r", "\n", "<", ">", '"')) or BIDI.search(name):
        problems.append(f"{where}: unsafe file name {name!r}")


def _check(label, data, ctype, problems):
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                member = info.filename
                if member.startswith("/") or ".." in member.split("/") or "\\" in member or ":" in member or BIDI.search(member):
                    problems.append(f"{label}: unsafe member {member!r}")
                body = z.read(info)
                if member.endswith((".xml", ".rels")):
                    try:
                        xml.dom.minidom.parseString(body)
                    except Exception as e:  # noqa: BLE001
                        problems.append(f"{label}!{member}: not well-formed XML ({e})")
                    if member.startswith("xl/worksheets/") and re.search(rb"<f[ >]", body):
                        problems.append(f"{label}!{member}: a formula element")
                    for t in re.findall(rb"<t[^>]*>([^<]*)</t>", body):
                        s = htmllib.unescape(t.decode("utf-8"))
                        if member.startswith("xl/") and s[:1] in TRIGGERS and not NUMBER.fullmatch(s):
                            problems.append(f"{label}!{member}: formula text {s[:40]!r}")
                        if BIDI.search(s):
                            problems.append(f"{label}!{member}: bidirectional control kept")
                else:
                    _check(f"{label}!{member}", body, "", problems)
        return
    if data[:4] == b"%PDF":
        if BIDI.search(data.decode("latin-1")):
            problems.append(f"{label}: bidirectional control in the PDF")
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        problems.append(f"{label}: not UTF-8")
        return
    low = label.lower()
    if "json" in ctype or low.endswith(".json"):
        try:
            json.loads(text, parse_constant=lambda c: problems.append(f"{label}: {c} in JSON"))
        except ValueError as e:
            problems.append(f"{label}: invalid JSON ({e})")
        return
    if BIDI.search(text):
        problems.append(f"{label}: bidirectional control kept")
    if "html" in ctype or low.endswith(".html"):
        if re.search(r"<img src=x onerror", text, re.I):
            problems.append(f"{label}: raw canary markup")
    elif low.endswith(".tf"):
        try:
            hcl_strict.parse(text)
        except Exception as e:  # noqa: BLE001
            problems.append(f"{label}: not strict HCL ({e})")
    elif low.endswith(".md") or "markdown" in ctype:
        from markdown_it import MarkdownIt
        rendered = MarkdownIt("commonmark", {"html": True}).enable("table").render(text).lower()
        if "<img" in rendered or 'href="javascript:' in rendered:
            problems.append(f"{label}: Markdown renders the canary as markup")
    elif low.endswith(".csv") or "csv" in ctype:
        for row in csv.reader(io.StringIO(text)):
            for cell in row:
                if cell[:1] in TRIGGERS and not NUMBER.fullmatch(cell):
                    problems.append(f"{label}: CSV formula {cell[:40]!r}")


def test_the_canary_tenant_reaches_the_jobs(canary_run):
    """ASVS V5.3.1 · CWE-79: the canaries reach the job results (so every check below sees them as data, not nothing)."""
    # Arrange
    _client, _app, runs = canary_run
    # Act
    seen = json.dumps(runs)
    # Assert
    assert "onerror=alert(2)" in seen and runs["path"].get("report_id") and runs["zpa"].get("report_id")


@pytest.mark.parametrize("name,template", EXPORTS, ids=[e[0] for e in EXPORTS])
def test_every_export_keeps_canary_names_inert(canary_run, name, template):
    """ASVS V5.3.1 · ASVS V5.3.3 · CWE-79 · CWE-1236 · CWE-94 · CWE-22 · CWE-451 · WSTG-INPV-11: in every format an export answers, canary names stay text: no markup, formula, live template, path or reordering control of their own. Table-driven over the export routes."""
    # Arrange
    client, app, runs = canary_run
    url = template.format(**runs)
    problems, answered = [], 0
    # Act
    for fmt in FORMATS if "download" not in name else ("",):
        _reset_rate_limit(app)
        r = client.get(url + (("&" if "?" in url else "?") + f"format={fmt}" if fmt else ""))
        assert r.status_code < 500, (url, fmt, r.text[:200])
        if r.status_code != 200:
            continue
        answered += 1
        disp = r.headers.get("content-disposition", "")
        m = re.search(r'filename="?([^";]+)', disp)
        _check_name(m.group(1) if m else "", f"{name} [{fmt}]", problems)
        _check(f"{name} [{fmt}] {m.group(1) if m else ''}", r.content, r.headers.get("content-type", ""), problems)
    # Assert
    assert answered, f"{name}: no format answered"
    assert problems == [], problems


# ── URL-valued sinks the HTML sink scan does not see ───────────────────
# tests/html_sink_scan.py follows values into innerHTML and markup. Pages
# built since also set URLs through element builders (h('a', {href: x})),
# setAttribute, .href / .src, window.open and location: a tenant value
# there is a javascript: link however well it is escaped. Every such value
# must be a literal, an encoded app path or a blob URL, or be reviewed here
# with the reason it cannot carry tenant data.
_URL_SINK = re.compile(
    r"""(?:[{,]\s*['"]?(?:href|src|srcdoc|formaction|xlink:href)['"]?\s*:\s*(?P<a>[^,}\n]+))"""
    r"""|(?:\.(?:href|src|action|srcdoc)\s*=(?!=)\s*(?P<b>[^;\n]+))"""
    r"""|(?:setAttribute(?:NS)?\(\s*(?:null\s*,\s*)?['"](?:href|src|action|xlink:href|formaction|srcdoc)['"]\s*,\s*(?P<c>[^)\n]+))"""
    r"""|(?:window\.open\(\s*(?P<d>[^,)\n]+))"""
    r"""|(?:\blocation(?:\.href)?\s*=(?!=)\s*(?P<e>[^;\n]+))""")
_SAFE_URL = re.compile(r"""^(['"])[^'"]*\1$|^`[^`$]*`$|^URL\.createObjectURL\(|^`/[^`]*\$\{encodeURIComponent\(|^'/[^']*'\s*\+\s*encodeURIComponent\(""")
URL_SINK_REVIEWED = {
    ("static/data_flow.js", "`#dfRow-${it.i}`"): "an in-page anchor to a table row; it.i is the row's numeric index",
    ("static/flow_anim.js", "{ x: 18, y: 8, w: W - 36, h: 44 }"): "pos.src is the source box's position in the picture, not a URL",
    ("static/flow_anim.js", "{ x: 18, y: Math.round(H / 2 - 22), w: 150, h: 44 }"): "pos.src is the source box's position in the picture, not a URL",
    ("static/advanced.js", "u.pathname + u.search"): "the page's own link with the assessor added through URLSearchParams",
    ("static/find_anything.js", "x.href || ''"): "x is a static/explain.js catalogue entry (app paths only)",
    ("static/find_anything.js", "x.href"): "x is a static/explain.js catalogue entry (app paths only)",
    ("static/find_anything.js", "(window.DLP_EXPLAIN && window.DLP_EXPLAIN[pagesFor(o)[0]] || {"): "the explain.js catalogue's own path",
    ("static/find_anything.js", "n.href"): "a workspace note's link: workspace_notes.clean_href allows only paths in this app",
    ("static/find_anything.js", "target.href || ''"): "sent to /api/workspace/notes, which keeps only paths in this app (clean_href)",
    ("static/path_list.js", "open"): "/report/operations?fix= with the id through encodeURIComponent",
    ("static/posture_banner.js", "'/report/posture' + (hash || ''"): "a fixed page with the page's own fragment",
    ("static/pov.js", "/^https:\\/\\//i.test(String(l.url || '')) ? String(l.url) : '#'"): "the test kit's links (constants in pov.py, EICAR_LINKS and the other kit lists), linked only when https, else '#'",
    ("static/simple.js", "a.href"): "fixAction()'s app path for a finding's fix",
    ("static/ui_auth.js", "ssoStatus.sso_login_url || '/api/auth/sso/login'"): "the server's fixed SSO path (/api/auth/sso/login)",
    ("static/ui_auth.js", "status.sso_login_url || '/login'"): "the server's fixed sign-in paths (/api/auth/sso/login, or the team server's /login)",
    ("static/zcc_fleet.js", "url"): "URL.createObjectURL of the downloaded export",
    ("static/fleet_dns.js", "url"): "URL.createObjectURL of the DNS records file built in the page",
    ("static/net_ranges.js", "url"): "URL.createObjectURL of the downloaded allowlist",
    ("static/find_anything.js", "href"): "'/report/path#categories=' with the host through encodeURIComponent (Category lookup)",
}


def _url_sinks():
    out = []
    for folder in ("static", "browser_extension"):
        for fn in sorted(os.listdir(os.path.join(ROOT_DIR, folder))):
            if not fn.endswith(".js"):
                continue
            rel = f"{folder}/{fn}"
            for line in open(os.path.join(ROOT_DIR, rel), encoding="utf-8"):
                if line.lstrip().startswith(("//", "*", "/*")):
                    continue
                for m in _URL_SINK.finditer(line):
                    v = next(g for g in m.groups() if g is not None).strip().rstrip(")").strip()
                    if not _SAFE_URL.match(v):
                        out.append((rel, v[:80]))
    return out


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_every_url_valued_sink_in_the_browser_code_is_safe_or_reviewed():
    """ASVS V5.3.3 · ASVS V5.1.5 · CWE-79 · CWE-601 · WSTG-CLNT-01 · WSTG-CLNT-04: every href/src/action set from a value, every window.open and location change, takes a literal, an encoded app path, a blob URL or a reviewed value (never tenant text, which would be a javascript: link)."""
    # Act
    unreviewed = sorted({s for s in _url_sinks() if s not in URL_SINK_REVIEWED})
    # Assert
    assert unreviewed == [], unreviewed


def test_the_url_sink_review_has_no_stale_entries():
    """ASVS V14.1.1 · CWE-1164: every reviewed URL sink still exists (a removed one is dropped from the list)."""
    # Act
    found = set(_url_sinks())
    # Assert
    assert sorted(set(URL_SINK_REVIEWED) - found) == []


@pytest.mark.parametrize("code,flagged", [
    ("h('a', { href: rule.url, text: 'x' })", True), ("a.href = data.link;", True), ("el.setAttribute('src', row.icon)", True),
    ("window.open(r.link, '_blank')", True), ("location.href = d.next;", True),
    ("h('a', { href: '/help#glossary' })", False), ("a.href = URL.createObjectURL(blob);", False),
    ("window.open(`/report/view?tool=${encodeURIComponent(kind)}`, '_blank')", False),
])
def test_the_url_sink_scan_finds_what_it_must(code, flagged):
    """ASVS V5.3.3 · CWE-79: the scan flags a data value in a URL sink and passes literals, encoded paths and blob URLs."""
    # Act
    hits = [next(g for g in m.groups() if g is not None).strip().rstrip(")").strip() for m in _URL_SINK.finditer(code)]
    # Assert
    assert any(not _SAFE_URL.match(v) for v in hits) is flagged, hits
