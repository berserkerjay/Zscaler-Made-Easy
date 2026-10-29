"""HAR import on the Path analyzer: the HAR file is parsed in the browser
(static/har_parse.js, run here under node) and only host names with their
request counts leave it; the batch endpoint reads the tenant once and
traces every host, Stop ends it between hosts, and the results export as
CSV or JSON. Fakes only: no tenant is called."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

import path_analyzer as pa
from test_data_flow import ROUTES
from test_path_analyzer import FULL, SCOPE_ALL, LookupCl, _lookup_client  # noqa: F401
from test_ssl_flow import CATALOGUE

class MultiLookup(LookupCl):
    """ZIA's URL lookup answers every URL of the request, echoing each."""
    def post(self, ep, body=None):
        self.lookups.append((ep, body))
        assert ep == "/zia/urlLookup", "only the read-only URL lookup may be posted"
        return [dict(self.LOOKUP.get(u, {"urlClassifications": []}), url=u) for u in body], 200


def _multi():
    return MultiLookup(ROUTES, CATALOGUE)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARSER = os.path.join(ROOT, "static", "har_parse.js")
node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

SECRETS = ("sessionid=COOKIE-VALUE-123", "COOKIE-VALUE-123", "Bearer TOKEN-abc-999", "TOKEN-abc-999", "s3cr3t-query-token",
           "ssn=123-45-6789", "123-45-6789", "/private/path/report.pdf", "hunter2-password", "x-api-key-value-777")


def _entry(url, method="GET", body=None, body_size=None, cookie=True):
    req = {"method": method, "url": url, "httpVersion": "HTTP/2",
           "headers": [{"name": "Authorization", "value": "Bearer TOKEN-abc-999"}, {"name": "X-Api-Key", "value": "x-api-key-value-777"}],
           "cookies": [{"name": "sessionid", "value": "COOKIE-VALUE-123"}] if cookie else [],
           "queryString": [{"name": "token", "value": "s3cr3t-query-token"}], "headersSize": 400,
           "bodySize": body_size if body_size is not None else (len(body.encode()) if body is not None else 0)}
    if body is not None:
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": body,
                           "params": [{"name": "password", "value": "hunter2-password"}]}
    return {"startedDateTime": "2026-10-20T10:00:00.000Z", "time": 12, "request": req,
            "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": "sessionid=COOKIE-VALUE-123"}],
                         "cookies": [], "content": {"size": 10, "mimeType": "text/html", "text": "ssn=123-45-6789"}},
            "cache": {}, "timings": {}}


def _har(entries):
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}})


def _parse(text, **opts):
    script = ("const p = require(process.argv[1]); let s = ''; process.stdin.on('data', d => s += d);"
              "process.stdin.on('end', () => process.stdout.write(JSON.stringify(p.parse(s, JSON.parse(process.argv[2])))));")
    r = subprocess.run(["node", "-e", script, PARSER, json.dumps(opts)], input=text, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout, json.loads(r.stdout)


@node
def test_the_parser_keeps_hosts_and_counts_and_nothing_else():
    text = _har([
        _entry("https://drive.example.com/private/path/report.pdf?token=s3cr3t-query-token", "POST", body="ssn=123-45-6789&password=hunter2-password"),
        _entry("https://drive.example.com/other", "GET"),
        _entry("https://Drive.Example.com:8443/x", "PUT", body="abc"),
        _entry("http://plain.example.org/", "GET"),
        _entry("https://user:hunter2-password@login.example.net/", "POST", body_size=0),
        _entry("https://203.0.113.10/upload", "POST", body=None, body_size=2048),
        _entry("wss://chat.example.com/socket", "GET"),
        _entry("data:text/plain,hello"), _entry("chrome-extension://abcdef/x.js"), _entry("not a url"),
        {"request": None}, "garbage", {"request": {"url": 42}},
    ])
    raw, out = _parse(text)
    assert out["ok"] and out["error"] is None and out["entries"] == 13 and out["skipped"] == 6
    hosts = {h["host"]: h for h in out["hosts"]}
    assert set(hosts) == {"drive.example.com", "plain.example.org", "login.example.net", "203.0.113.10", "chat.example.com"}
    d = hosts["drive.example.com"]
    assert d["requests"] == 3 and d["uploads"] == 2 and d["methods"] == ["POST", "GET", "PUT"] and d["schemes"] == ["https"]
    assert d["bytes_sent"] == len("ssn=123-45-6789&password=hunter2-password") + 3
    assert hosts["login.example.net"]["uploads"] == 0, "a POST with an empty body is not an upload"
    assert hosts["203.0.113.10"]["uploads"] == 1 and hosts["203.0.113.10"]["bytes_sent"] == 2048
    assert hosts["plain.example.org"]["schemes"] == ["http"] and hosts["chat.example.com"]["schemes"] == ["wss"]
    # Uploads first: where data leaves.
    assert out["hosts"][0]["host"] == "drive.example.com" and not out["capped"] and out["more"] == []
    # No header, cookie, query, path, body or URL credential leaves the parser.
    for s in SECRETS + ("user:", "Authorization", "sessionid"):
        assert s not in raw, s
    assert set(out["hosts"][0]) == {"host", "schemes", "requests", "methods", "uploads", "bytes_sent"}


@node
@pytest.mark.parametrize("text, words", [
    ("{not json", "not valid JSON"),
    ("", "empty"),
    (json.dumps({"nolog": 1}), 'no "log"'),
    (json.dumps({"log": {"entries": {}}}), "no list of entries"),
    (json.dumps({"log": {"entries": []}}), "no requests"),
    (_har([_entry("data:x"), _entry("ftp://files.example.com/")]), "no web host"),
    (json.dumps([1, 2, 3]), 'no "log"'),
])
def test_malformed_and_empty_files_are_refused_in_words(text, words):
    _, out = _parse(text)
    assert out["ok"] is False and words in out["error"] and out["hosts"] == []


@node
def test_a_file_over_the_size_limit_is_refused_before_it_is_parsed():
    text = _har([_entry(f"https://h{i}.example.com/") for i in range(50)])
    _, out = _parse(text, maxBytes=1024 * 1024)
    assert out["ok"]
    _, out = _parse(text, maxBytes=1000)
    assert out["ok"] is False and "larger than" in out["error"] and "MB" in out["error"]
    js = open(PARSER, encoding="utf-8").read()
    assert "const MAX_BYTES = 100 * 1024 * 1024;" in js and "const MAX_HOSTS = 200;" in js
    page = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    assert "file.size > HarParse.MAX_BYTES" in page, "the page checks the size before reading the file"


@node
def test_over_the_host_cap_the_rest_are_listed_never_silently_dropped():
    entries = [_entry(f"https://site{i:03d}.example.com/") for i in range(240)]
    entries += [_entry("https://zz-upload.example.com/u", "POST", body="data")]
    _, out = _parse(_har(entries))
    assert out["ok"] and out["capped"] and out["total_hosts"] == 241
    assert len(out["hosts"]) == 200 and len(out["more"]) == 41
    assert out["hosts"][0]["host"] == "zz-upload.example.com", "a host that received an upload is always analyzed first"
    assert {h["host"] for h in out["hosts"]}.isdisjoint({m["host"] for m in out["more"]})
    page = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    words = open(os.path.join(ROOT, "static", "har_parse.js"), encoding="utf-8").read()
    # The note counts every host left out (HarParse.leftOut: more_total), and lists the ones kept.
    assert "more host(s) not analyzed" in words and "host(s) left out" in words
    assert "HarParse.leftOut(p)" in page and "<summary>${E(L.summary)}</summary>" in page


def test_the_page_sends_only_host_names_and_counts():
    page = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    assert '<script src="/static/har_parse.js"></script>' in page and page.index("data_flow.js") < page.index("har_parse.js")
    assert 'id="paHarBtn"' in page and 'id="paHar"' in page and "/api/path-analyzer/batch/start" in page
    send = page.split("const hosts = p.hosts.map(h => (")[1].split("));")[0]
    assert send == "{ host: h.host, requests: h.requests, uploads: h.uploads, bytes_sent: h.bytes_sent, methods: h.methods, schemes: h.schemes }"
    assert "never uploaded" in page and "<h3" not in page
    for needle in ("aria-sort", "/export?format=", "/host?host=", "Back to the HAR results", "Only hosts that received uploads"):
        assert needle in page, needle


# ---------------------------------------------------------------------------
# The batch
# ---------------------------------------------------------------------------

HOSTS = ["casino.example", "mail.example.com", "updates.vendor.com", "chat.openai.com"]


def test_one_tenant_read_and_one_lookup_request_answer_every_host():
    c = _multi()
    single = _lookup_client()
    pa.analyze(single, "casino.example", scope=FULL)
    logs = []
    out = pa.analyze_batch(c, HOSTS, scope=FULL, log=logs.append,
                           stats={"casino.example": {"requests": 3, "uploads": 1, "bytes_sent": 99, "methods": ["POST"]}})
    assert c.reads == single.reads, "the tenant is read once, as for one destination"
    assert [ep for ep, _ in c.lookups] == ["/zia/urlLookup"] and c.lookups[0][1] == HOSTS, "one lookup request for every host"
    rows = {r["host"]: r for r in out["rows"]}
    assert rows["casino.example"]["outcome"] == "blocked" and rows["casino.example"]["deciding_rule"] == "Block gambling"
    assert rows["casino.example"]["stops_at"] == "URL filtering" and rows["casino.example"]["requests"] == 3 and rows["casino.example"]["uploads"] == 1
    assert rows["mail.example.com"]["outcome"] == "blind" and rows["mail.example.com"]["deciding_rule"] == "No decrypt webmail"
    assert rows["updates.vendor.com"]["outcome"] == "bypassed" and rows["updates.vendor.com"]["stops_at"] == "Client Connector app profile"
    assert rows["chat.openai.com"]["outcome"] == "inspected" and rows["chat.openai.com"]["dlp_rules"]
    assert out["snapshot_for_cache"] and out["stopped"] is None and set(out["analyses"]) == set(HOSTS)
    assert out["analyses"]["mail.example.com"]["verdict"]["outcome"] == "blind"
    # The same verdict as the single-destination analysis.
    assert out["analyses"]["casino.example"]["verdict"] == pa.analyze(_lookup_client(), "casino.example", scope=FULL)["verdict"]
    assert any(l.startswith("Tracing 4 of 4: chat.openai.com") for l in logs)


def test_lookups_go_a_hundred_hosts_at_a_time_and_a_refusal_is_said():
    c = _multi()
    hosts = [f"h{i}.example.com" for i in range(150)]
    got = pa.lookup_many(c, hosts)
    assert [len(b) for _, b in c.lookups] == [100, 50] and set(got) == set(hosts) and all(v["error"] is None for v in got.values())

    class Refuses(LookupCl):
        def post(self, ep, body=None):
            return {"error": "forbidden"}, 403
    bad = pa.lookup_many(Refuses(ROUTES, CATALOGUE), ["a.example.com"])
    assert "HTTP 403" in bad["a.example.com"]["error"] and bad["a.example.com"]["categories"] == []
    # An answer that echoes no url is matched by position; a missing answer is said, never invented.
    class NoEcho(LookupCl):
        def post(self, ep, body=None):
            return [{"urlClassifications": ["GAMBLING"]}], 200
    got = pa.lookup_many(NoEcho(ROUTES, CATALOGUE), ["a.example.com", "b.example.com"])
    assert got["a.example.com"]["categories"] == ["GAMBLING"] and "no answer" in got["b.example.com"]["error"]


def test_stop_between_hosts_keeps_the_hosts_done_and_lists_the_rest():
    import re
    c = _multi()
    seen = []

    def cancel():
        return len(seen) >= 2
    out = pa.analyze_batch(c, HOSTS, scope=FULL, cancel=cancel, log=lambda l: seen.append(l) if re.match(r"Tracing \d+ of", l) else None)
    assert out["stopped"].startswith("You clicked Stop after 2 of 4") and [r["host"] for r in out["rows"]] == HOSTS[:2]
    assert out["not_analyzed"] == HOSTS[2:] and out["snapshot_for_cache"] is None
    # Stop before anything: nothing is read, not even the lookup.
    c2 = _multi()
    out = pa.analyze_batch(c2, HOSTS, scope=FULL, cancel=lambda: True)
    assert out["rows"] == [] and out["not_analyzed"] == HOSTS and not c2.lookups and c2.reads == 0
    with pytest.raises(ValueError, match="At most 200"):
        pa.analyze_batch(c2, [f"h{i}.example.com" for i in range(201)], scope=FULL)


def _follow(t, job):
    deadline = time.time() + 30
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


CREDS = dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}, **SCOPE_ALL)


def test_the_batch_endpoint_runs_as_a_job_reuses_the_read_and_exports(monkeypatch, tmp_path):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    audit_log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(audit_log))
    c = _multi()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    hosts = [{"host": "casino.example", "requests": 4, "uploads": 1, "bytes_sent": 120, "methods": ["GET", "POST", "<script>"], "cookie": "COOKIE-VALUE-123"},
             {"host": "mail.example.com", "requests": 2}, "updates.vendor.com", {"host": "not a host"}, {"host": "https://x.example.com/path"}]
    r = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=hosts))
    assert r.status_code == 200 and r.json()["kind"] == "path-batch" and r.json()["hosts"] == 3 and r.json()["skipped"] == 2, r.text
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "done", snap.get("error")
    res = snap["result"]
    assert [x["host"] for x in res["rows"]] == ["casino.example", "mail.example.com", "updates.vendor.com"]
    row = res["rows"][0]
    assert row["methods"] == ["GET", "POST"] and row["uploads"] == 1 and row["requests"] == 4 and "cookie" not in row
    assert res["report_id"].startswith("dataflow-") and res["tenant_label"] == "acme (production)" and res["counts"] == {"blocked": 1, "blind": 1, "bypassed": 1}
    assert "secret-secret-secret" not in json.dumps(snap)
    # A row opens that host's full analysis, without a tenant call.
    reads, lookups = c.reads, len(c.lookups)
    full = t.get(f"/api/path-analyzer/batch/{res['batch_id']}/host", params={"host": "mail.example.com"}).json()
    assert full["verdict"]["outcome"] == "blind" and full["trace"]["hops"] and full["report_id"] == res["report_id"]
    assert t.get(f"/api/path-analyzer/batch/{res['batch_id']}/host", params={"host": "nope.example"}).status_code == 404
    # Exports: CSV through csv_safe, JSON with the rows.
    csv_text = t.get(f"/api/path-analyzer/batch/{res['batch_id']}/export?format=csv").text
    assert csv_text.splitlines()[0].startswith("host,requests,uploads,bytes_sent,methods,outcome,stops_at,deciding_rule,dlp_rules")
    assert "casino.example,4,1,120,GET; POST,blocked,URL filtering,Block gambling" in csv_text
    js = t.get(f"/api/path-analyzer/batch/{res['batch_id']}/export?format=json").json()
    assert [x["host"] for x in js["rows"]] == [x["host"] for x in res["rows"]] and "analyses" not in js
    # The next run reuses the read: only the lookup is asked.
    r2 = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=["chat.openai.com"], report_id=res["report_id"]))
    snap2 = _follow(t, r2.json()["job_id"])
    assert snap2["status"] == "done" and c.reads == reads and len(c.lookups) == lookups + 1 and not snap2["result"]["fresh_read"]
    assert snap2["result"]["report_id"] == res["report_id"]
    # The audit log records that hosts were sent, never which.
    log = audit_log.read_text(encoding="utf-8")
    assert "/api/path-analyzer/batch/start" in log and '"har_hosts":"[omitted: 5 items]"' in log
    for h in ("casino.example", "mail.example.com", "COOKIE-VALUE-123", "secret-secret-secret"):
        assert h not in log, h


def test_the_batch_is_refused_before_signing_in_when_nothing_can_be_read(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient

    def no_sign_in(req):
        raise AssertionError("signed in before the request was checked")
    monkeypatch.setattr(srv, "_build_client", no_sign_in)
    t = TestClient(srv.app)
    base = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    r = t.post("/api/path-analyzer/batch/start", json=dict(base, scopes=["compliance"], channels={}, from_page=True, har_hosts=["casino.example"]))
    assert r.status_code == 400 and "secret-secret-secret" not in r.text
    r = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=[f"h{i}.example.com" for i in range(201)]))
    assert r.status_code == 400 and "At most 200" in r.json()["detail"]
    r = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=["not a host", ""]))
    assert r.status_code == 400 and "No hostname" in r.json()["detail"]


def test_stop_on_the_batch_job_ends_it_with_the_hosts_done(monkeypatch):
    import dlp_api_server as srv
    import pack_jobs
    from fastapi.testclient import TestClient

    c = _multi()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    real = pa.analyze
    calls = []

    def slow_analyze(*a, **kw):
        calls.append(a[1])
        if len(calls) == 3:   # Stop pressed while the third host starts
            pack_jobs.cancel(pack_jobs.current().id)
        return real(*a, **kw)
    monkeypatch.setattr(pa, "analyze", slow_analyze)
    t = TestClient(srv.app)
    r = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=HOSTS))
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and snap["result"]["stopped"].startswith("You clicked Stop after 2 of 4")
    assert [x["host"] for x in snap["result"]["rows"]] == HOSTS[:2] and snap["result"]["not_analyzed"] == HOSTS[2:]
    assert snap["result"]["report_id"] == "", "a read cut short by Stop is not kept for the next run"
    # Stop before the start answered: the job begins stopped and reads nothing.
    c2 = _multi()
    monkeypatch.setattr(srv, "_build_client", lambda req: c2)
    token = "earlystop12345678"
    assert t.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token}).status_code == 200
    r = t.post("/api/path-analyzer/batch/start", json=dict(CREDS, har_hosts=HOSTS), headers={"X-Start-Token": token})
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and snap["result"]["rows"] == [] and c2.reads == 0 and not c2.lookups
