"""Container healthcheck: is the app answering on its own port?

Probes /api/ping over HTTPS when the configuration turns HTTPS on (the
team server with ZSCALER_TLS or a certificate pair), and over plain HTTP
otherwise, so a TLS team server is not reported unhealthy forever.
Loopback only; nothing but the ping path is requested.
"""
import ssl
import sys
import urllib.request

import server_tls

PORT = 8000


def url() -> str:
    scheme = "https" if server_tls.requested() else "http"
    return f"{scheme}://127.0.0.1:{PORT}/api/ping"


def _context():
    # Liveness probe to our own loopback listener: the certificate names the
    # public host (or is self-signed), never 127.0.0.1, so it is not verified.
    # No credentials or data are sent; only the status code is read.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def main() -> int:
    target = url()
    try:
        ctx = _context() if target.startswith("https://") else None
        with urllib.request.urlopen(target, timeout=4, context=ctx) as resp:  # nosec B310 # fixed http(s) loopback URL, no user input
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
