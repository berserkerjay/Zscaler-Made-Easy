"""Real local TLS/CONNECT checks on every native OS, with a synthetic CA.

This proves configured-bundle/proxy behavior. It does NOT prove an enterprise
Zscaler certificate, OS root-store enrollment, corporate PAC, or live tenant.
No TLS-verification bypasses and no external network are used.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import io
import ipaddress
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import threading
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

ROOT = Path(__file__).resolve().parents[1]


def certificate(name, key, issuer, issuer_key, *, ca=False, ip=True):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False,
                                             key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                                             key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
    if not ca:
        names = [x509.DNSName('localhost')]
        if ip:
            names.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        builder = (builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture(scope='module')
def tls(tmp_path_factory):
    root = tmp_path_factory.mktemp('native tls with spaces')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic Native Test CA')])
    ca = certificate('Synthetic Native Test CA', key, issuer, key, ca=True)
    ca_path = root / 'approved test root.pem'
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, 'w') as out:
        out.writestr('native_smoke_marker.py', '# Synthetic download-only marker\n')
        out.writestr('native_smoke_marker-0.0.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: native-smoke-marker\nVersion: 0.0.0\n')
        out.writestr('native_smoke_marker-0.0.0.dist-info/WHEEL', 'Wheel-Version: 1.0\nGenerator: local-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
        out.writestr('native_smoke_marker-0.0.0.dist-info/RECORD', '')
    payload = wheel.getvalue()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = payload if self.path.endswith('.whl') else b'synthetic TLS fixture'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    servers = []
    result = {'ca': str(ca_path), 'hash': hashlib.sha256(payload).hexdigest()}
    for label, include_ip in (('valid', True), ('wrong_host', False)):
        leaf = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = certificate('localhost', leaf, ca.subject, key, ip=include_ip)
        cert_path, key_path = root / (label + '.pem'), root / (label + '.key')
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(leaf.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        result[label] = f'https://127.0.0.1:{server.server_port}'
    yield result
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture
def proxy(tls):
    connections = []
    allowed = {int(tls[label].rsplit(':', 1)[1]) for label in ('valid', 'wrong_host')}
    class Connect(http.server.BaseHTTPRequestHandler):
        def do_CONNECT(self):
            host, port = self.path.rsplit(':', 1)
            if host not in ('127.0.0.1', 'localhost') or int(port) not in allowed:
                self.send_error(403)
                return
            connections.append(self.path)
            with socket.create_connection((host, int(port)), timeout=3) as upstream:
                self.send_response(200, 'Connection established')
                self.end_headers()
                sockets = (self.connection, upstream)
                while True:
                    ready, _, _ = select.select(sockets, [], [], 3)
                    if not ready:
                        return
                    for source in ready:
                        try:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
                        except OSError:
                            return
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Connect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {'url': f'http://127.0.0.1:{server.server_port}', 'connections': connections}
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


@pytest.fixture(autouse=True)
def clean_trust_and_proxy(monkeypatch):
    for key in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'PIP_CERT', 'PIP_TRUSTED_HOST', 'PIP_PROXY',
                'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
                'ZSCALER_UPDATE_VERIFY_TLS', 'ZSCALER_UPDATE_PROXY'):
        monkeypatch.delenv(key, raising=False)


def safe_get(monkeypatch, url):
    import zscaler_update_check as updates
    monkeypatch.setattr(updates, 'ALLOWED_HOSTS', {'127.0.0.1'})
    return updates._safe_get(url)


def test_default_trust_rejects_unapproved_tls_root(tls, monkeypatch):
    body, status, error = safe_get(monkeypatch, tls['valid'])
    assert body is None and status == 0 and 'TLS error' in error


def test_configured_ca_bundle_verifies_real_https(tls, monkeypatch):
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls['ca'])
    body, status, error = safe_get(monkeypatch, tls['valid'])
    assert (body, status, error) == (b'synthetic TLS fixture', 200, '')


def test_approved_root_does_not_disable_hostname_validation(tls, monkeypatch):
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls['ca'])
    body, status, error = safe_get(monkeypatch, tls['wrong_host'])
    assert body is None and status == 0 and 'TLS error' in error


def test_https_proxy_environment_tunnels_verified_tls(tls, proxy, monkeypatch):
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls['ca'])
    monkeypatch.setenv('HTTPS_PROXY', proxy['url'])
    body, status, error = safe_get(monkeypatch, tls['valid'])
    assert status == 200 and body and not error
    assert len(proxy['connections']) == 1


def test_no_proxy_loopback_bypasses_configured_proxy(tls, proxy, monkeypatch):
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls['ca'])
    monkeypatch.setenv('HTTPS_PROXY', proxy['url'])
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    assert safe_get(monkeypatch, tls['valid'])[1] == 200
    assert proxy['connections'] == []


def test_app_proxy_override_uses_verified_connect_tunnel(tls, proxy, monkeypatch):
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', tls['ca'])
    monkeypatch.setenv('ZSCALER_UPDATE_PROXY', proxy['url'])
    assert safe_get(monkeypatch, tls['valid'])[1] == 200
    assert len(proxy['connections']) == 1


def test_proxy_transport_does_not_trust_an_unapproved_root(tls, proxy, monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', proxy['url'])
    body, status, error = safe_get(monkeypatch, tls['valid'])
    assert body is None and status == 0 and 'TLS error' in error
    assert len(proxy['connections']) == 1


def pip_download(tmp_path, tls, *, approved=True, proxy=None, valid_hash=True):
    env = os.environ.copy()
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_NO_INDEX='1',
               PYTHONPATH=str(ROOT / 'tests/native_support'), NATIVE_GUARD_MARKER=str(tmp_path / 'guard'),
               NATIVE_EGRESS_LOG=str(tmp_path / 'egress.jsonl'))
    if approved:
        env['PIP_CERT'] = tls['ca']
    if proxy:
        env['HTTPS_PROXY'] = proxy['url']
    digest = tls['hash'] if valid_hash else '0' * 64
    requirements = tmp_path / 'fixture requirements.txt'
    url = tls['valid'].replace('127.0.0.1', 'localhost')
    requirements.write_text(f"{url}/native_smoke_marker-0.0.0-py3-none-any.whl --hash=sha256:{digest}\n")
    result = subprocess.run([sys.executable, '-m', 'pip', 'download', '--no-cache-dir', '--no-deps', '--no-index',
                             '--retries', '0', '--timeout', '5', '--require-hashes', '-r', str(requirements), '--dest', str(tmp_path / 'downloads')],
                            env=env, capture_output=True, text=True, timeout=30)
    assert (tmp_path / 'guard').is_file(), 'Subprocess network guard was not active'
    assert not (tmp_path / 'egress.jsonl').exists(), 'pip attempted non-loopback traffic'
    return result


def test_pip_accepts_hash_pinned_download_with_configured_ca(tls, tmp_path):
    result = pip_download(tmp_path, tls)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(list((tmp_path / 'downloads').glob('*.whl'))) == 1


def test_pip_rejects_unapproved_tls_root(tls, tmp_path):
    result = pip_download(tmp_path, tls, approved=False)
    assert result.returncode != 0 and 'CERTIFICATE_VERIFY_FAILED' in result.stdout + result.stderr
    assert not list((tmp_path / 'downloads').glob('*.whl'))


def test_pip_rejects_wrong_hash_even_over_approved_tls(tls, tmp_path):
    result = pip_download(tmp_path, tls, valid_hash=False)
    assert result.returncode != 0 and 'DO NOT MATCH THE HASHES' in result.stdout + result.stderr
    assert not list((tmp_path / 'downloads').glob('*.whl'))


def test_pip_proxy_and_ca_work_together_without_disabling_tls(tls, proxy, tmp_path):
    result = pip_download(tmp_path, tls, proxy=proxy)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(proxy['connections']) == 1


def test_synthetic_ca_and_leaf_pass_strict_native_openssl_validation(tls):
    context = ssl.create_default_context(cafile=tls['ca'])
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.check_hostname = True
    assert context.verify_mode == ssl.CERT_REQUIRED
    port = int(tls['valid'].rsplit(':', 1)[1])
    with socket.create_connection(('127.0.0.1', port), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname='localhost') as secure:
            secure.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            assert b'200 OK' in secure.recv(4096)
