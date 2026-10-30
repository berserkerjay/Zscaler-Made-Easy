"""Built-in HTTPS for the server (optional; off by default).

    ZSCALER_TLS_CERT, ZSCALER_TLS_KEY   a certificate (PEM, the chain after
                                        the server's own) and its private
                                        key: the server answers HTTPS only
    ZSCALER_TLS=self-signed             no certificate to hand: one is made
                                        on the first start (an ECDSA P-256
                                        key, valid 397 days, for localhost,
                                        this machine's name and any name in
                                        ZSCALER_TLS_HOSTNAMES) and kept in
                                        tls/ beside the app's data, owner-
                                        only; its SHA-256 fingerprint is
                                        printed at every start so a person
                                        can check it in the browser before
                                        trusting it
    ZSCALER_TLS_HOSTNAMES               extra DNS names or IP addresses for
                                        the self-signed certificate,
                                        comma-separated

The certificate is made with the `cryptography` package the app already
pins (requirements.lock, through PyJWT); nothing here does cryptography by
hand. Team mode (team_server.py) needs TLS to serve beyond this computer
(security.require_safe_bind), and sends HSTS while it is on.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional

SELF_SIGNED_VALUES = ("self-signed", "selfsigned", "self_signed", "1", "on", "yes", "true")
CERT_FILE = "server_cert.pem"
KEY_FILE = "server_key.pem"
VALID_DAYS = 397
HSTS_VALUE = "max-age=31536000"


def requested() -> bool:
    """Does the configuration ask for HTTPS (a certificate pair, or self-signed)?"""
    return bool(os.environ.get("ZSCALER_TLS_CERT", "").strip() or os.environ.get("ZSCALER_TLS_KEY", "").strip()
                or os.environ.get("ZSCALER_TLS", "").strip().lower() in SELF_SIGNED_VALUES)


def tls_dir() -> str:
    env = os.environ.get("DLP_CHECK_TLS_DIR", "").strip()
    if env:
        return env
    try:
        import tenant_profiles
        base = os.path.dirname(os.path.abspath(tenant_profiles.store_path()))
    except Exception:  # noqa: BLE001
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "tls")


def config_errors() -> List[str]:
    """What stops HTTPS from starting as configured (empty: fine, or not asked for)."""
    cert = os.environ.get("ZSCALER_TLS_CERT", "").strip()
    key = os.environ.get("ZSCALER_TLS_KEY", "").strip()
    if not (cert or key):
        return []
    errors = []
    if bool(cert) != bool(key):
        errors.append("set both ZSCALER_TLS_CERT and ZSCALER_TLS_KEY (or neither)")
    for name, path in (("ZSCALER_TLS_CERT", cert), ("ZSCALER_TLS_KEY", key)):
        if path and not os.path.isfile(path):
            errors.append(f"{name} names a file that does not exist")
    return errors


def fingerprint(cert_path: str) -> str:
    """The certificate's SHA-256 fingerprint as browsers show it (AB:CD:...)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    digest = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _names() -> List[str]:
    names = ["localhost", "127.0.0.1", "::1"]
    try:
        host = socket.gethostname()
        if host:
            names.append(host)
    except OSError:
        pass
    extra = [n.strip() for n in os.environ.get("ZSCALER_TLS_HOSTNAMES", "").split(",") if n.strip()]
    for n in extra:
        if len(n) <= 253 and all(c.isalnum() or c in ".-:" for c in n):
            names.append(n)
    out: List[str] = []
    for n in names:
        if n.lower() not in [o.lower() for o in out]:
            out.append(n)
    return out


def generate_self_signed(folder: str) -> Dict[str, str]:
    """Make a self-signed certificate and key in `folder` (0700; the key
    0600). Returns their paths."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import safe_files
    safe_files.private_makedirs(folder)
    key = ec.generate_private_key(ec.SECP256R1())
    names = _names()
    sans: List[Any] = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Zscaler Made Easy team server (self-signed)")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path = os.path.join(folder, KEY_FILE)
    cert_path = os.path.join(folder, CERT_FILE)
    safe_files.write_private_atomic(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                serialization.NoEncryption()).decode("ascii"))
    safe_files.write_private_atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    return {"cert": cert_path, "key": key_path}


def ensure() -> Optional[Dict[str, Any]]:
    """The certificate to serve with, or None when HTTPS is not asked for:
    {cert, key, fingerprint, self_signed, generated}. A self-signed pair is
    made on the first start and reused after; one past its end date is
    made again. Raises RuntimeError when the configuration is incomplete."""
    if not requested():
        return None
    errors = config_errors()
    if errors:
        raise RuntimeError("HTTPS is configured but cannot start: " + "; ".join(errors) + ".")
    cert = os.environ.get("ZSCALER_TLS_CERT", "").strip()
    key = os.environ.get("ZSCALER_TLS_KEY", "").strip()
    if cert and key:
        return {"cert": cert, "key": key, "fingerprint": fingerprint(cert), "self_signed": False, "generated": False}
    folder = tls_dir()
    cert, key = os.path.join(folder, CERT_FILE), os.path.join(folder, KEY_FILE)
    generated = False
    if not (os.path.isfile(cert) and os.path.isfile(key)) or _expired(cert):
        paths = generate_self_signed(folder)
        cert, key, generated = paths["cert"], paths["key"], True
    return {"cert": cert, "key": key, "fingerprint": fingerprint(cert), "self_signed": True, "generated": generated}


def _expired(cert_path: str) -> bool:
    try:
        from cryptography import x509
        with open(cert_path, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        end = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=_dt.timezone.utc)
        return end <= _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1)
    except (OSError, ValueError):
        return True


_STATUS: Dict[str, Any] = {}


def remember(info: Optional[Dict[str, Any]]) -> None:
    """What main() started with, for the Team server page (no key material)."""
    _STATUS.clear()
    if info:
        _STATUS.update({k: info.get(k) for k in ("fingerprint", "self_signed", "generated")})


def status() -> Dict[str, Any]:
    return {"on": bool(_STATUS) or requested(), **_STATUS}


# ── HTTP → HTTPS redirect (ZSCALER_TLS_REDIRECT_PORT) ───────────────────
import re as _re

_HOST_RE = _re.compile(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?$")


def redirect_port() -> Optional[int]:
    """The plain-HTTP port that only redirects to HTTPS, when one is set
    (ZSCALER_TLS_REDIRECT_PORT, e.g. 80 or 8080) and HTTPS is on."""
    raw = os.environ.get("ZSCALER_TLS_REDIRECT_PORT", "").strip()
    if not raw or not requested():
        return None
    try:
        port = int(raw)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def redirect_app(https_port: int):
    """A tiny ASGI app: every plain-HTTP request gets a 308 to the same path
    on https://<the host it asked for>:<https_port>. It serves nothing else,
    sets no cookie, and a Host header that is not a host name gets 400 (no
    redirect to whatever a caller wrote)."""
    async def app(scope, receive, send):
        if scope.get("type") != "http":
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        host = headers.get("host", "").strip()
        m = _HOST_RE.match(host)
        if not m:
            await send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Bad Host header."})
            return
        name = m.group(1)
        path = scope.get("raw_path") or scope.get("path", "/").encode("latin-1")
        if isinstance(path, (bytes, bytearray)):
            path = bytes(path).decode("latin-1")
        if not path.startswith("/") or path.startswith("//"):
            path = "/"
        qs = (scope.get("query_string") or b"").decode("latin-1")
        target = f"https://{name}{'' if https_port == 443 else f':{https_port}'}{path}" + (f"?{qs}" if qs else "")
        await send({"type": "http.response.start", "status": 308,
                    "headers": [(b"location", target.encode("latin-1")), (b"content-length", b"0"), (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": b""})
    return app


def start_redirect_server(host: str, port: int, https_port: int):
    """Run the redirect app on host:port in a daemon thread; returns the thread."""
    import threading
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(redirect_app(https_port), host=host, port=port, log_level="warning", access_log=False))
    t = threading.Thread(target=server.run, name="https-redirect", daemon=True)
    t.start()
    return t
