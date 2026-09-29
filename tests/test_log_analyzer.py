"""Log Analyzer: Client Connector log bundles and PAC files explained in
plain English, analysed in memory with archive caps and redaction."""
from __future__ import annotations

import base64
import io
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import log_analyzer as la
import security


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


LOG = """2026-09-01 08:00:01.100(-0500)[1234:11] INF ZSATray: App Version: 4.4.0.256, OS: Windows 11 Enterprise
2026-09-01 08:00:02.100(-0500)[1234:11] INF ZSAService: User jane.doe@acme.com login initiated
2026-09-01 08:00:03.100(-0500)[1234:11] INF ZSATunnel: Captive portal detected on network
2026-09-01 08:00:04.100(-0500)[1234:11] ERR ZSATunnel: Tunnel to gateway.zscalerthree.net failed: DTLS handshake timed out
2026-09-01 08:00:05.100(-0500)[1234:11] ERR ZSATunnel: Tunnel state changed to TUNNEL_STATE_DOWN
2026-09-01 08:00:06.100(-0500)[1234:11] WRN ZSATunnel: Z-Tunnel 2.0 blocked, falling back to Z-Tunnel 1.0
2026-09-01 08:00:07.100(-0500)[1234:11] ERR ZSAService: SAML authentication failed: token=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV password=hunter2
2026-09-01 08:00:08.100(-0500)[1234:11] ERR ZSAService: HTTP 407 Proxy Authentication Required from proxy.corp.local
2026-09-01 08:00:09.100(-0500)[1234:11] INF ZSATunnel: Tunnel state changed to TUNNEL_STATE_ZERO_TRUST_ON
"""


# ── Line parsing ────────────────────────────────────────────────────
def test_parse_line_recognises_zcc_syslog_and_us_formats():
    p = la.parse_line("2026-09-01 08:00:04.100(-0500)[1234:11] ERR ZSATunnel: Tunnel failed")
    assert p["ts"] == "2026-09-01 08:00:04" and p["level"] == "error"
    p = la.parse_line("Sep  1 08:00:04 mac ZSATunnel[55]: WARN something")
    assert p["ts"].endswith("-09-01 08:00:04") and p["level"] == "warn"
    p = la.parse_line("9/1/2026 08:00:04 INFO ZSATray started")
    assert p["ts"] == "2026-09-01 08:00:04" and p["level"] == "info"
    assert la.parse_line("no timestamp here")["ts"] == ""


# ── Signatures and the story ────────────────────────────────────────
def test_findings_are_plain_english_ordered_and_cross_referenced():
    r = la.analyze_logs([("ZSATray.log", LOG)])
    keys = [f["key"] for f in r["findings"]]
    assert keys[0] in ("tunnel_down", "auth_failed") and r["findings"][0]["severity"] == "critical"
    assert {"captive_portal", "auth_failed", "tunnel_down", "tunnel2_fallback", "proxy_auth"} <= set(keys)
    auth = next(f for f in r["findings"] if f["key"] == "auth_failed")
    for field in ("title", "what", "means"):
        assert len(auth[field]) > 20
    assert auth["do"] and all(isinstance(s, str) for s in auth["do"])
    assert "captive portal" in auth["context"].lower()
    assert auth["first"] == "2026-09-01 08:00:07" and auth["files"][0]["name"] == "ZSATray.log"
    f = r["facts"]
    assert f["client_versions"] == ["4.4.0.256"] and f["operating_systems"] == ["Windows 11"]
    assert f["users"] == ["jane.doe@acme.com"] and f["clouds"] == ["zscalerthree"]
    assert f["last_tunnel_state"] == "TUNNEL_STATE_ZERO_TRUST_ON" and "Z-Tunnel 2.0" in f["tunnel_versions"]
    assert r["period"] == {"first": "2026-09-01 08:00:01", "last": "2026-09-01 08:00:09"}
    assert r["levels"]["error"] == 4


def test_evidence_is_redacted_and_bounded():
    r = la.analyze_logs([("a.log", LOG)])
    auth = next(f for f in r["findings"] if f["key"] == "auth_failed")
    line = auth["evidence"][0]["line"]
    assert "hunter2" not in line and "abcdefghijklmnop" not in line and "[redacted]" in line
    assert all(len(e["line"]) <= la.EVIDENCE_WIDTH for f in r["findings"] for e in f["evidence"])
    assert all(len(f["evidence"]) <= la.MAX_EVIDENCE for f in r["findings"])
    assert "hunter2" not in " ".join(t["message"] for t in r["top_errors"])
    red = la.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
    assert "eyJ" not in red and "redacted" in red


def test_single_transient_events_are_not_findings():
    one = "2026-09-01 08:00:04 ERR ZSATunnel: request timed out\n"
    r = la.analyze_logs([("a.log", one)])
    assert "timeouts" not in {f["key"] for f in r["findings"]}
    r = la.analyze_logs([("a.log", one * 6)])
    assert "timeouts" in {f["key"] for f in r["findings"]}


def test_healthy_logs_give_a_calm_verdict():
    r = la.analyze([{"name": "ZSATray.log", "content": "2026-09-01 08:00:01 INF ZSATray: App Version 4.4.0.1\n2026-09-01 08:00:02 INF ZSATunnel: Tunnel state changed to TUNNEL_STATE_ZERO_TRUST_ON\n"}])
    assert r["verdict"]["level"] == "ok" and r["logs"]["findings"] == []
    assert r["checked"] and all({"key", "severity", "title"} <= set(c) for c in r["checked"])


# ── Unpacking ───────────────────────────────────────────────────────
def test_zip_bundle_is_read_binary_skipped_names_never_used_as_paths():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ZSCALER_LOGS/ZSATray.log", LOG)
        z.writestr("../../etc/passwd.log", "2026-09-01 08:00:01 INF harmless\n")
        z.writestr("ZSCALER_LOGS/bin.dat", b"\x00\x01\x02")
        z.writestr("ZSCALER_LOGS/utf16.log", "\ufeff2026-09-01 08:00:01 ERR ZSAService: login failed for user\n".encode("utf-16"))
    members, notes = la.expand([{"name": "C:\\Users\\x\\zscaler_logs.zip", "content": _b64(buf.getvalue()), "encoding": "base64"}])
    names = [n for n, _ in members]
    assert names == ["ZSATray.log", "passwd.log", "utf16.log"]
    assert any("bin.dat" in n and "binary" in n for n in notes)
    r = la.analyze([{"name": "zscaler_logs.zip", "content": _b64(buf.getvalue()), "encoding": "base64"}])
    assert "auth_failed" in {f["key"] for f in r["logs"]["findings"]}
    assert any(f["name"] == "utf16.log" and f["lines"] == 1 for f in r["logs"]["files"])


def test_tar_and_gzip_bundles_are_read():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        data = LOG.encode()
        info = tarfile.TarInfo("logs/ZSATunnel.log"); info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    members, _ = la.expand([{"name": "logs.tgz", "content": _b64(buf.getvalue()), "encoding": "base64"}])
    assert [n for n, _ in members] == ["ZSATunnel.log"]
    import gzip
    members, _ = la.expand([{"name": "ZSATray.log.gz", "content": _b64(gzip.compress(LOG.encode())), "encoding": "base64"}])
    assert [n for n, _ in members] == ["ZSATray.log"]


def test_archive_caps_stop_a_hostile_bundle(monkeypatch):
    monkeypatch.setattr(la, "MAX_MEMBERS", 2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(5):
            z.writestr(f"f{i}.log", "2026-09-01 08:00:01 INF x\n")
    members, notes = la.expand([{"name": "many.zip", "content": _b64(buf.getvalue()), "encoding": "base64"}])
    assert len(members) == 2 and any("stopped after 2 files" in n for n in notes)
    monkeypatch.setattr(la, "MAX_MEMBERS", 600)
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 100)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.log", "A" * 10000)
    members, notes = la.expand([{"name": "bomb.zip", "content": _b64(buf.getvalue()), "encoding": "base64"}])
    assert members == [] and any("bomb.log" in n and "larger than" in n for n in notes)
    # a zip inside a zip inside a zip is not opened
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep.log", "2026-09-01 08:00:01 INF x\n")
    mid = io.BytesIO()
    with zipfile.ZipFile(mid, "w") as z:
        z.writestr("inner.zip", inner.getvalue())
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("mid.zip", mid.getvalue())
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 48 * 1024 * 1024)
    members, notes = la.expand([{"name": "outer.zip", "content": _b64(outer.getvalue()), "encoding": "base64"}])
    assert members == [] and any("nested archive" in n for n in notes)


def test_bad_uploads_raise_value_errors():
    with pytest.raises(ValueError):
        la.analyze([])
    with pytest.raises(ValueError, match="base64"):
        la.analyze([{"name": "x.zip", "content": "%%%not base64%%%", "encoding": "base64"}])
    with pytest.raises(ValueError, match="nothing readable"):
        la.analyze([{"name": "x.bin", "content": _b64(b"\x00\x00\x00"), "encoding": "base64"}])


# ── PAC files ───────────────────────────────────────────────────────
PAC = """function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || shExpMatch(host, "*.local")) return "DIRECT";
  if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (shExpMatch(host, "*.dropbox.com")) return "DIRECT";
  if (isInNet(host, "8.0.0.0", "255.0.0.0")) return "DIRECT";
  return "PROXY gateway.zscalerthree.net:80; DIRECT";
}"""


def test_pac_findings_name_the_risky_bypasses_and_the_hardcoded_gateway():
    p = la.analyze_pac("proxy.pac", PAC)
    s = p["summary"]
    assert s["default"] == "proxy" and s["gateways"] == ["gateway.zscalerthree.net"] and s["macros"] == []
    by = {(b["kind"], b["value"]): b["risk"] for b in s["bypasses"]}
    assert by[("shExpMatch", "*.dropbox.com")] == "data-channel"
    assert by[("isInNet", "8.0.0.0")] == "public-range" and by[("isInNet", "10.0.0.0")] == "ok"
    assert ("isInNet", "255.0.0.0") not in by, "a mask is not a bypass"
    titles = [f["title"] for f in p["findings"]]
    assert any("bypass" in t and "around Zscaler" in t for t in titles)
    assert any("hard-coded" in t for t in titles) and any("Only one gateway" in t for t in titles)
    assert any("isInNet(host" in t for t in titles) and any("Fail-open" in t for t in titles)
    assert not any("No bypass for private" in t for t in titles)
    assert p["findings"][0]["severity"] == "high"


def test_pac_default_direct_and_not_a_pac():
    p = la.analyze_pac("bypass.pac", 'function FindProxyForURL(url, host) { if (shExpMatch(host, "*.corp.local")) return "PROXY ${GATEWAY}:80"; return "DIRECT"; }')
    assert any("default answer is DIRECT" in f["title"] for f in p["findings"])
    assert any("No bypass for private" in f["title"] for f in p["findings"])
    p = la.analyze_pac("notes.js", "var x = 1;")
    assert p["findings"][0]["severity"] == "critical" and "not a working PAC" in p["findings"][0]["title"]
    p = la.analyze_pac("broken.pac", "function FindProxyForURL(url, host) { if (x) { return \"DIRECT\"; }")
    assert any("Unbalanced braces" in f["title"] for f in p["findings"])


def test_pac_is_detected_by_content_and_a_good_pac_passes():
    good = 'function FindProxyForURL(url, host) {\n if (isPlainHostName(host) || isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";\n return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";\n}'
    r = la.analyze([{"name": "download.txt", "content": good}])
    assert r["logs"] is None and r["pac"][0]["kind"] == "pac"
    sev = {f["severity"] for f in r["pac"][0]["findings"]}
    assert sev <= {"info"} and r["verdict"]["level"] == "ok"
    assert r["pac"][0]["summary"]["macros"] == ["${GATEWAY}", "${SECONDARY_GATEWAY}"]


# ── HTTP surface ────────────────────────────────────────────────────
def _client(with_token=True):
    c = TestClient(srv.app)
    if with_token:
        c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_endpoint_and_pages(monkeypatch):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "test-token-abc123")
    c = _client()
    r = c.post("/api/logs/analyze", json={"files": [{"name": "ZSATray.log", "content": LOG}]})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["verdict"]["level"] == "critical" and body["logs"]["findings"]
    assert c.post("/api/logs/analyze", json={"files": []}).status_code == 400
    assert c.post("/api/logs/analyze", json={"files": [{"name": "x.zip", "content": "%%%", "encoding": "base64"}]}).status_code == 400
    cat = c.get("/api/logs/catalogue").json()
    assert cat["max_body_mb"] >= 1 and len(cat["checked"]) >= 20 and cat["accepts"]
    anon = _client(with_token=False)
    assert anon.post("/api/logs/analyze", json={"files": [{"name": "a.log", "content": "x"}]}).status_code == 401
    page = anon.get("/report/logs")
    assert page.status_code == 200 and "Log analyzer" in page.text and 'for="laFiles"' in page.text and "/api/logs/analyze" in page.text
    assert anon.get("/help").status_code == 200 and "What does everything do" in anon.get("/help").text
