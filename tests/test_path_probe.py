"""ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: "Test from here" is an opt-in, bounded observation that cannot be turned into a request forger.

path_probe: one destination per request, an explicit click (confirm=true)
by an authenticated viewer, ports on an allow-list (443, 80, 8443, 8080),
loopback, link-local (cloud metadata), multicast, unspecified and reserved
addresses refused, the first resolved address pinned, short timeouts, at
most RATE_PER_MINUTE a minute and one at a time, nothing sent but a TCP
connect and a TLS ClientHello, nothing cached; the result compared with
the analyzer's prediction.

Every connection here is to a loopback test server this file starts (the
suite's offline guard refuses anything else); certificates are made up in
the test with the cryptography package. Loopback is allowed only through
the module's test switch (ALLOW_LOOPBACK) and the server's ephemeral port
only by patching the allow-list.
"""
from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import path_probe as pp

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "probe-ui-token-" + "7" * 32


# ── Made-up certificates and loopback servers ─────────────────────────
def _cert(tmp: Path, issuer_cn: str, issuer_o: str, name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_o)])
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "inspected.example")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("inspected.example"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(ca_key, hashes.SHA256()))
    cp, kp = tmp / f"{name}.crt", tmp / f"{name}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(cp), str(kp)


class Server:
    """A loopback server: TLS with the given certificate, plain TCP, or a
    TCP server that never answers a ClientHello. Records every connection
    and every byte a client sent after the handshake."""

    def __init__(self, mode: str = "tls", cert=None):
        self.mode, self.accepted, self.app_bytes = mode, 0, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.ctx = None
        if mode == "tls":
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(*cert)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.accepted += 1
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        conn.settimeout(2.0)
        try:
            if self.mode == "silent":
                self.stop.wait(1.5)
                return
            s = self.ctx.wrap_socket(conn, server_side=True) if self.mode == "tls" else conn
            got = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                got += chunk
            self.app_bytes.append(got)
        except Exception:  # noqa: BLE001 — a client that verifies and refuses our made-up CA ends the handshake
            self.app_bytes.append(b"")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


@pytest.fixture
def loopback(monkeypatch, tmp_path):
    """Arrange: loopback allowed (the module's test switch), the rate limit reset, servers closed after."""
    monkeypatch.setattr(pp, "ALLOW_LOOPBACK", True)
    pp.reset_rate_limit()
    servers = []

    def make(mode="tls", issuer=("Zscaler Intermediate Root CA (zscalerthree.net) (t)", "Zscaler Inc.")):
        s = Server(mode, _cert(tmp_path, issuer[0], issuer[1], f"c{len(servers)}") if mode == "tls" else None)
        servers.append(s)
        monkeypatch.setattr(pp, "ALLOWED_PORTS", tuple(pp.ALLOWED_PORTS) + tuple(x.port for x in servers))
        return s
    yield make
    for s in servers:
        s.close()
    pp.reset_rate_limit()


def _wait(cond, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not cond():
        time.sleep(0.01)   # bounded wait for the server thread to record the connection
    return cond()


# ── The observation ───────────────────────────────────────────────────
def test_a_zscaler_issued_certificate_is_read_and_agrees_with_inspection(loopback):
    """ASVS V9.1.1 · CWE-295: issuer, subject, names, TLS version and trust are read; a Zscaler issuer agrees with "inspected by ZIA"."""
    # Arrange
    s = loopback()
    # Act
    out = pp.run(f"https://127.0.0.1:{s.port}/", prediction={"outcome": "enforce", "decrypted": True, "reaches_zscaler": True})
    # Assert
    c = out["tls"]["certificate"]
    assert out["dns"]["ok"] and out["tcp"]["ok"] and out["tls"]["ok"] and out["tls"]["version"] in ("TLSv1.2", "TLSv1.3")
    assert c["issuer_cn"].startswith("Zscaler Intermediate Root CA") and c["issuer_o"] == "Zscaler Inc." and c["zscaler"] is True
    assert c["subject_cn"] == "inspected.example" and c["sans"] == ["inspected.example", "127.0.0.1"] and "der" not in c
    assert out["tls"]["trusted"] is False and out["tls"]["trust_error"]
    ssl_line = next(x for x in out["comparison"] if x["topic"] == "SSL inspection")
    assert ssl_line["agrees"] is True and ssl_line["predicted"] == "inspected by ZIA (decrypted)"
    assert ssl_line["observed"].startswith("certificate issued by Zscaler Intermediate Root CA")
    assert "from the computer running this app" in out["where"]


def test_the_destinations_own_certificate_differs_from_a_predicted_inspection(loopback):
    """ASVS V9.1.1 · CWE-295: a certificate from another issuer contradicts "inspected by ZIA" and agrees with "not decrypted"."""
    # Arrange
    s = loopback(issuer=("Example Public CA", "Example Trust Ltd"))
    # Act
    yes = pp.run(f"https://127.0.0.1:{s.port}/", prediction={"decrypted": True})
    pp.reset_rate_limit()
    no = pp.run(f"https://127.0.0.1:{s.port}/", prediction={"decrypted": False, "reaches_zscaler": False})
    # Assert
    a = next(x for x in yes["comparison"] if x["topic"] == "SSL inspection")
    b = {x["topic"]: x for x in no["comparison"]}
    assert a["agrees"] is False and "not Zscaler's" in a["note"] and yes["tls"]["certificate"]["zscaler"] is False
    assert b["SSL inspection"]["agrees"] is True and b["Reaches Zscaler"]["agrees"] is True


def test_nothing_but_a_connect_and_a_client_hello_is_sent(loopback):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: no HTTP request, body or credential: the server receives zero application bytes; port 80 is a bare connect."""
    # Arrange
    tls = loopback()
    plain = loopback("tcp")
    # Act
    pp.run(f"https://127.0.0.1:{tls.port}/upload?token=abc", prediction={"decrypted": True})
    pp.run(f"http://127.0.0.1:{plain.port}/form", prediction={})
    # Assert
    assert _wait(lambda: len(tls.app_bytes) >= 3 and len(plain.app_bytes) >= 1)
    assert tls.accepted == 3 and plain.accepted == 1   # TCP check, the handshake, the trust check; one bare connect
    assert all(b == b"" for b in tls.app_bytes + plain.app_bytes)


def test_plain_http_is_a_connect_only_and_says_so(loopback):
    """CWE-319: http:// is tested with a TCP connect only; no TLS is attempted and the comparison says it cannot see a block."""
    # Arrange
    s = loopback("tcp")
    # Act
    out = pp.run(f"http://127.0.0.1:{s.port}/", prediction={"outcome": "blocked", "stops_at": "URL filtering"})
    # Assert
    assert out["tcp"]["ok"] and out["tls"]["attempted"] is False and out["tls"]["ok"] is None
    blk = next(x for x in out["comparison"] if x["topic"] == "Block")
    assert blk["agrees"] is None and "cannot see a block" in blk["note"]


def test_a_handshake_that_never_comes_times_out(loopback, monkeypatch):
    """ASVS V12.6.1 · CWE-400: a server that accepts and never answers the ClientHello is given up on after TLS_TIMEOUT."""
    # Arrange
    s = loopback("silent")
    monkeypatch.setattr(pp, "TLS_TIMEOUT", 0.3)
    # Act
    t0 = time.monotonic()
    out = pp.run(f"https://127.0.0.1:{s.port}/")
    # Assert
    assert out["tcp"]["ok"] and out["tls"]["ok"] is False and time.monotonic() - t0 < 2.5
    assert out["comparison"][0]["topic"] == "Prediction"


def test_a_slow_resolver_is_given_up_on(loopback, monkeypatch):
    """ASVS V12.6.1 · CWE-400: a name lookup that does not answer within DNS_TIMEOUT is reported as failed, nothing connected."""
    # Arrange
    monkeypatch.setattr(pp, "DNS_TIMEOUT", 0.2)
    monkeypatch.setattr(pp.socket, "getaddrinfo", lambda *a, **k: time.sleep(1.0) or [])
    # Act
    out = pp.run("https://slow.example/")
    # Assert
    assert out["dns"]["ok"] is False and "within" in out["dns"]["error"] and out["tcp"]["ok"] is None


def test_a_closed_port_is_an_answer_not_an_error(loopback):
    """CWE-755: a refused connection is reported in words and the prediction that it reaches the destination is contradicted."""
    # Arrange
    s = loopback("tcp")
    port = s.port
    s.close()
    # Act
    out = pp.run(f"http://127.0.0.1:{port}/", prediction={"outcome": "enforce"})
    # Assert
    assert out["tcp"]["ok"] is False and out["tcp"]["error"]
    assert next(x for x in out["comparison"] if x["topic"] == "Reachable")["agrees"] is False


# ── What may be tested ────────────────────────────────────────────────
@pytest.mark.parametrize("dest,port", [("example.com", 22), ("example.com:6379", None), ("https://example.com:8081/", None),
                                       ("example.com", 0), ("example.com", 70000), ("example.com", "x")])
def test_ports_outside_the_allow_list_are_refused_before_anything_is_sent(dest, port, monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: a port not in 443, 80, 8443, 8080 (typed or in the URL) is refused; nothing is resolved."""
    # Arrange
    looked = []
    monkeypatch.setattr(pp.socket, "getaddrinfo", lambda *a, **k: looked.append(a) or [])
    pp.reset_rate_limit()
    # Act / Assert
    with pytest.raises(pp.Refused):
        pp.run(dest, port)
    assert looked == [] and len(pp._RECENT) == 0


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.8.9.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.251",
                                "240.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "0.1.2.3"])
def test_addresses_that_reach_this_computer_or_metadata_are_refused(ip):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: loopback, link-local (metadata), multicast, unspecified, reserved and their IPv4-mapped forms are refused."""
    assert pp.address_refusal(ip)


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.1.1", "100.64.3.4", "203.0.113.10", "2001:db8::1"])
def test_private_zpa_and_public_addresses_may_be_tested(ip):
    """CWE-918: internal and ZPA synthetic addresses are what the analyzer is about, so they are allowed (documented in the threat model)."""
    assert pp.address_refusal(ip) is None


def test_a_typed_loopback_address_is_refused_before_any_packet(monkeypatch):
    """ASVS V12.6.1 · CWE-918: with the app's setting, 127.0.0.1 is refused and nothing connects."""
    # Arrange
    pp.reset_rate_limit()
    monkeypatch.setattr(pp, "ALLOW_LOOPBACK", False)
    connects = []
    monkeypatch.setattr(pp.socket, "create_connection", lambda *a, **k: connects.append(a))
    # Act / Assert
    with pytest.raises(pp.Refused, match="loopback"):
        pp.run("https://127.0.0.1/")
    assert connects == []


def test_the_first_resolved_address_is_pinned_and_checked(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · CWE-350: a name whose first answer is the metadata address is refused; a later safe answer is never tried instead."""
    # Arrange
    pp.reset_rate_limit()
    connects = []
    monkeypatch.setattr(pp.socket, "create_connection", lambda *a, **k: connects.append(a))
    # Act / Assert
    with pytest.raises(pp.Refused, match="link-local"):
        pp.observe("https://rebind.example/", resolve=lambda host, port, t: ["169.254.169.254", "203.0.113.10"])
    assert connects == []


def test_the_rate_limit_and_one_at_a_time(loopback):
    """ASVS V11.1.4 · CWE-770: at most RATE_PER_MINUTE tests a minute, and a second test while one runs is refused (429)."""
    # Arrange
    s = loopback("tcp")
    dest = f"http://127.0.0.1:{s.port}/"
    for _ in range(pp.RATE_PER_MINUTE):
        pp.run(dest, now=1000.0)
    # Act / Assert
    with pytest.raises(pp.Busy, match="times a minute"):
        pp.run(dest, now=1001.0)
    pp.run(dest, now=1061.0)   # a minute later it runs again
    assert pp._BUSY.acquire(blocking=False)
    try:
        with pytest.raises(pp.Busy, match="Another Test from here"):
            pp.run(dest, now=2000.0)
    finally:
        pp._BUSY.release()


# ── The prediction and the comparison ────────────────────────────────
def test_the_prediction_is_bounded_to_known_fields():
    """ASVS V5.1.3 · CWE-20: only known keys, booleans as booleans, text cut to length."""
    p = pp.normalize_prediction({"outcome": "x" * 999, "decrypted": "yes", "zpa": True, "evil": "<script>", "headline": "h" * 999})
    assert set(p) == {"outcome", "headline", "reaches_zscaler", "decrypted", "zpa", "stops_at"}
    assert len(p["outcome"]) == 40 and len(p["headline"]) == 300 and p["decrypted"] is None and p["zpa"] is True
    assert pp.normalize_prediction("nope") is None


def test_a_zpa_synthetic_address_agrees_with_a_zpa_prediction():
    """CWE-670: an answer in 100.64.0.0/10 agrees with "carried by ZPA" and contradicts "not carried"."""
    obs = {"dns": {"ok": True, "addresses": ["100.64.0.7"], "zpa_synthetic": True}, "tcp": {"ok": True}, "tls": {"attempted": False, "certificate": {}}}
    yes = pp.compare({"zpa": True, "outcome": "zpa_allowed"}, obs)
    no = pp.compare({"zpa": False}, obs)
    assert yes[0]["topic"] == "ZPA" and yes[0]["agrees"] is True and no[0]["agrees"] is False


def test_a_certificate_that_cannot_be_read_is_unknown_never_a_crash():
    """CWE-20 · CWE-755: garbage or oversized certificate bytes give "unknown" fields."""
    assert pp.parse_certificate(b"not a certificate")["read"] is False
    assert pp.parse_certificate(b"0" * (pp.MAX_CERT_BYTES + 1))["read"] is False
    assert pp.is_zscaler_issuer("Zscaler Root CA", None) and not pp.is_zscaler_issuer("DigiCert", "DigiCert Inc")


# ── The route ─────────────────────────────────────────────────────────
def test_the_route_needs_an_explicit_click(monkeypatch):
    """ASVS V4.1.3 · CWE-352 · CWE-918: without confirm=true nothing is resolved or sent (400)."""
    # Arrange
    looked = []
    monkeypatch.setattr(pp.socket, "getaddrinfo", lambda *a, **k: looked.append(a) or [])
    # Act
    r = TestClient(srv.app).post("/api/path-analyzer/test-from-here", json={"destination": "example.com"})
    # Assert
    assert r.status_code == 400 and "click" in r.json()["detail"] and looked == []


def test_the_route_can_be_switched_off_for_an_install(monkeypatch):
    """ASVS V14.1.3 · CWE-1188: ZSCALER_TEST_FROM_HERE=0 turns it off (403), nothing sent."""
    monkeypatch.setenv("ZSCALER_TEST_FROM_HERE", "0")
    r = TestClient(srv.app).post("/api/path-analyzer/test-from-here", json={"destination": "example.com", "confirm": True})
    assert r.status_code == 403 and "turned off" in r.json()["detail"]


def test_the_route_answers_once_and_is_never_cached(loopback):
    """ASVS V8.2.1 · CWE-524: each request tests again (two requests, two connections) and the answer is no-store."""
    # Arrange
    s = loopback("tcp")
    c = TestClient(srv.app)
    body = {"destination": f"http://127.0.0.1:{s.port}/", "confirm": True, "prediction": {"outcome": "enforce"}}
    # Act
    r1, r2 = c.post("/api/path-analyzer/test-from-here", json=body), c.post("/api/path-analyzer/test-from-here", json=body)
    # Assert
    assert r1.status_code == r2.status_code == 200 and _wait(lambda: s.accepted == 2)
    assert "no-store" in r1.headers["cache-control"] and r1.json()["port"] == s.port


@pytest.mark.parametrize("body,code", [({"destination": "example.com", "port": 22, "confirm": True}, 400),
                                       ({"destination": "not a host", "confirm": True}, 400),
                                       ({"destination": "https://169.254.169.254/latest/meta-data/", "confirm": True}, 400)])
def test_the_route_refuses_in_words(body, code):
    """ASVS V5.1.3 · CWE-918 · WSTG-INPV-19: a disallowed port, a bad destination or the metadata address is a 400 that says why."""
    pp.reset_rate_limit()
    r = TestClient(srv.app).post("/api/path-analyzer/test-from-here", json=body)
    assert r.status_code == code and ("Nothing was sent" in r.text or "not a URL" in r.text), r.text


def test_the_route_is_behind_the_ui_token_and_the_origin_check(monkeypatch):
    """ASVS V4.1.1 · V13.2.3 · CWE-306 · CWE-352 · WSTG-SESS-05: without the UI token it is a 401; from another origin a 403; neither sends anything."""
    # Arrange
    import security
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setenv("ZSCALER_UI_TOKEN", TOKEN)
    monkeypatch.delenv("ZSCALER_SSO_ENABLED", raising=False)
    monkeypatch.setattr(security, "_ui_token", None)
    looked = []
    monkeypatch.setattr(pp.socket, "getaddrinfo", lambda *a, **k: looked.append(a) or [])
    c = TestClient(srv.app)
    body = {"destination": "example.com", "confirm": True}
    # Act
    anon = c.post("/api/path-analyzer/test-from-here", json=body)
    cross = c.post("/api/path-analyzer/test-from-here", json=body, headers={"X-DLP-Check-Token": TOKEN, "Origin": "https://evil.example"})
    # Assert
    assert anon.status_code == 401 and cross.status_code == 403 and looked == []


def test_the_threat_model_is_written_down():
    """ASVS V1.1.2 · CWE-1059: the module and SECURITY.md carry the threat model: who, what, ports, what is sent, limits, nothing kept."""
    doc = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    code = (ROOT / "path_probe.py").read_text(encoding="utf-8")
    for words in ("Test from here", "443, 80, 8443, 8080", "169.254.169.254", "confirm=true", "no-store", "ZSCALER_TEST_FROM_HERE"):
        assert words in doc and words in code, words
