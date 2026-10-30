"""Let's Encrypt (or any ACME CA) certificates through the dns-01 challenge,
with the DNS record made through Cloudflare's API. Optional and OFF by
default; nothing here runs unless ZSCALER_TLS=acme.

    ZSCALER_TLS=acme              get the server's certificate from an ACME CA
    ZSCALER_ACME_DOMAINS          the name(s) on the certificate, comma-separated
                                  (required; DNS names only)
    ZSCALER_ACME_EMAIL            optional contact address for the CA
    ZSCALER_ACME_DIRECTORY        the CA's directory (https only; default
                                  Let's Encrypt; "staging" = Let's Encrypt staging)
    ZSCALER_ACME_DNS_WAIT         seconds to wait for the TXT record to spread
                                  (default 30)

The Cloudflare API token (Zone.DNS edit on the zone) is kept in the
operating system's credential store like the app's other secrets, or, only
with DLP_CHECK_SECRET_STORE=file, in an owner-only file:

    python server_acme.py set-cloudflare-token     (asks for it; never echoed)
    python server_acme.py issue                    (get or renew now)

Declared outbound destinations, used only with ZSCALER_TLS=acme: the ACME
directory's host (acme-v02.api.letsencrypt.org by default; every address
the directory names must be on that same host) and api.cloudflare.com.
Every answer is size-capped and parsed defensively. A certificate is
renewed at start-up when it has fewer than 30 days left; a renewal that
fails keeps serving the old certificate while it is valid.

Cryptography: the account key and the certificate key are ECDSA P-256
keys made with the pinned `cryptography` package; requests are signed with
ES256 (RFC 8555 section 6.2, RFC 7518). Nothing is hand-made cryptography:
this module only lays out the JSON the protocol asks for.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

LETS_ENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
KEYRING_SERVICE = "dlp-check"
TOKEN_NAME = "acme-cloudflare-token"
ACCOUNT_KEY_FILE = "acme_account_key.pem"
TOKEN_FILE = "acme_cloudflare_token"
MAX_RESPONSE = 1024 * 1024
TIMEOUT = 15
RENEW_DAYS = 30
POLL_TRIES = 30
_sleep = time.sleep   # tests replace it


class AcmeError(RuntimeError):
    pass


def requested() -> bool:
    return os.environ.get("ZSCALER_TLS", "").strip().lower() == "acme"


def domains() -> List[str]:
    out = []
    for d in os.environ.get("ZSCALER_ACME_DOMAINS", "").split(","):
        d = d.strip().lower().rstrip(".")
        if d:
            if len(d) > 253 or not all(lbl and len(lbl) <= 63 and all(c.isalnum() or c == "-" for c in lbl)
                                        for lbl in (d[2:] if d.startswith("*.") else d).split(".")):
                raise AcmeError(f"ZSCALER_ACME_DOMAINS: {d[:60]!r} is not a DNS name.")
            out.append(d)
    if not out:
        raise AcmeError("ZSCALER_ACME_DOMAINS is not set: name the host name(s) the certificate is for.")
    return out


def directory_url() -> str:
    raw = os.environ.get("ZSCALER_ACME_DIRECTORY", "").strip()
    url = LETS_ENCRYPT_STAGING if raw.lower() == "staging" else (raw or LETS_ENCRYPT)
    if urlparse(url).scheme != "https":
        raise AcmeError("ZSCALER_ACME_DIRECTORY must be an https:// address.")
    return url


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── the Cloudflare token (credential store, or the opted-in file) ───────
def _keyring():
    try:
        import keyring  # type: ignore
        if keyring is None:
            return None
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001
        return None


def _token_path() -> str:
    import server_tls
    return os.path.join(server_tls.tls_dir(), TOKEN_FILE)


def set_cloudflare_token(token: str) -> str:
    token = (token or "").strip()
    if not token or len(token) > 512 or any(c.isspace() for c in token):
        raise AcmeError("That does not look like a Cloudflare API token.")
    kr = _keyring()
    if kr is not None:
        kr.set_password(KEYRING_SERVICE, TOKEN_NAME, token)
        return "credential store"
    if os.environ.get("DLP_CHECK_SECRET_STORE", "").strip().lower() != "file":
        raise AcmeError("No credential store is available here. Set DLP_CHECK_SECRET_STORE=file to keep the token in an owner-only "
                        "file instead (the same opt-in as remembered tenant secrets).")
    import safe_files
    safe_files.write_private_atomic(_token_path(), token)
    return "owner-only file"


def cloudflare_token() -> str:
    kr = _keyring()
    if kr is not None:
        try:
            tok = kr.get_password(KEYRING_SERVICE, TOKEN_NAME)
            if tok:
                return tok
        except Exception:  # noqa: BLE001
            pass
    try:
        with open(_token_path(), "r", encoding="utf-8") as f:
            tok = f.read().strip()
        if tok:
            return tok
    except OSError:
        pass
    raise AcmeError("No Cloudflare API token is stored: run  python server_acme.py set-cloudflare-token")


# ── HTTP, bounded ───────────────────────────────────────────────────────
def _json(resp) -> Any:
    raw = resp.content if hasattr(resp, "content") else b""
    if raw and len(raw) > MAX_RESPONSE:
        raise AcmeError("An answer was larger than expected; stopped.")
    try:
        import safe_files
        return safe_files.strict_json_loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise AcmeError("An answer was not valid JSON.") from None


class _Http:
    def __init__(self, session=None):
        if session is None:
            import requests
            session = requests.Session()
        self.s = session

    def get(self, url, **kw):
        return self.s.get(url, timeout=TIMEOUT, allow_redirects=False, **kw)

    def head(self, url, **kw):
        return self.s.head(url, timeout=TIMEOUT, allow_redirects=False, **kw)

    def post(self, url, **kw):
        return self.s.post(url, timeout=TIMEOUT, allow_redirects=False, **kw)

    def delete(self, url, **kw):
        return self.s.delete(url, timeout=TIMEOUT, allow_redirects=False, **kw)


# ── the ACME client (RFC 8555) ──────────────────────────────────────────
class AcmeClient:
    def __init__(self, account_key, directory: str, http: _Http):
        from cryptography.hazmat.primitives.asymmetric import ec
        if not isinstance(account_key, ec.EllipticCurvePrivateKey):
            raise AcmeError("The ACME account key must be an ECDSA P-256 key.")
        self.key = account_key
        self.http = http
        self.dir_url = directory
        self.host = urlparse(directory).hostname
        r = http.get(directory)
        if r.status_code != 200:
            raise AcmeError(f"The ACME directory answered {r.status_code}.")
        d = _json(r)
        for k in ("newNonce", "newAccount", "newOrder"):
            self._same_host(d.get(k))
        self.directory = d
        self.nonce: Optional[str] = None
        self.kid: Optional[str] = None

    def _same_host(self, url: Any) -> str:
        p = urlparse(str(url or ""))
        if p.scheme != "https" or p.hostname != self.host:
            raise AcmeError("The ACME server named an address that is not https on its own host; stopped.")
        return str(url)

    def jwk(self) -> Dict[str, str]:
        n = self.key.public_key().public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": _b64u(n.x.to_bytes(32, "big")), "y": _b64u(n.y.to_bytes(32, "big"))}

    def thumbprint(self) -> str:
        """RFC 7638: SHA-256 of the JWK's required members, sorted, no spaces."""
        return _b64u(hashlib.sha256(json.dumps(self.jwk(), sort_keys=True, separators=(",", ":")).encode()).digest())

    def _sign(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(self.key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _new_nonce(self) -> str:
        r = self.http.head(self.directory["newNonce"])
        n = r.headers.get("Replay-Nonce")
        if not n:
            raise AcmeError("The ACME server gave no nonce.")
        return n

    def post(self, url: str, payload: Optional[Dict[str, Any]], *, use_jwk: bool = False):
        """A signed POST (payload None: POST-as-GET). A badNonce is retried once."""
        self._same_host(url)
        for attempt in (1, 2):
            nonce = self.nonce or self._new_nonce()
            self.nonce = None
            protected = {"alg": "ES256", "nonce": nonce, "url": url}
            if use_jwk or not self.kid:
                protected["jwk"] = self.jwk()
            else:
                protected["kid"] = self.kid
            p64 = _b64u(json.dumps(protected).encode())
            b64 = "" if payload is None else _b64u(json.dumps(payload).encode())
            body = {"protected": p64, "payload": b64, "signature": _b64u(self._sign(f"{p64}.{b64}".encode()))}
            r = self.http.post(url, data=json.dumps(body), headers={"Content-Type": "application/jose+json"})
            self.nonce = r.headers.get("Replay-Nonce") or None
            if r.status_code == 400 and attempt == 1 and "badNonce" in str(_json(r).get("type") if r.content else ""):
                continue
            if r.status_code >= 400:
                err = _json(r) if r.content else {}
                raise AcmeError(f"The ACME server refused ({r.status_code}): {str(err.get('detail') or err.get('type') or '')[:200]}")
            return r
        raise AcmeError("The ACME server kept refusing the nonce.")

    def register(self, email: str = "") -> str:
        payload: Dict[str, Any] = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        r = self.post(self.directory["newAccount"], payload, use_jwk=True)
        self.kid = self._same_host(r.headers.get("Location"))
        return self.kid

    def poll(self, url: str, done: Tuple[str, ...], bad: Tuple[str, ...] = ("invalid",)) -> Dict[str, Any]:
        for _ in range(POLL_TRIES):
            obj = _json(self.post(url, None))
            st = obj.get("status")
            if st in done:
                return obj
            if st in bad:
                errs = [str((c.get("error") or {}).get("detail") or "") for c in obj.get("challenges") or [] if isinstance(c, dict)]
                raise AcmeError(f"The ACME server says {st}: {'; '.join(e for e in errs if e)[:300] or 'no detail'}")
            _sleep(2)
        raise AcmeError("The ACME server did not finish in time.")


# ── Cloudflare DNS ──────────────────────────────────────────────────────
class Cloudflare:
    def __init__(self, token: str, http: _Http):
        self.h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.http = http

    def _ok(self, r) -> Any:
        body = _json(r)
        if r.status_code >= 400 or not body.get("success"):
            errs = "; ".join(str(e.get("message")) for e in body.get("errors") or [] if isinstance(e, dict))[:200]
            raise AcmeError(f"Cloudflare refused ({r.status_code}): {errs or 'no detail'}")
        return body.get("result")

    def zone_for(self, name: str) -> str:
        labels = name.split(".")
        for i in range(len(labels) - 1):
            zone = ".".join(labels[i:])
            res = self._ok(self.http.get(f"{CLOUDFLARE_API}/zones", params={"name": zone}, headers=self.h))
            if isinstance(res, list) and res and isinstance(res[0], dict) and res[0].get("id"):
                return str(res[0]["id"])
        raise AcmeError(f"No Cloudflare zone this token can edit holds {name}.")

    def add_txt(self, zone: str, name: str, value: str) -> str:
        res = self._ok(self.http.post(f"{CLOUDFLARE_API}/zones/{zone}/dns_records", headers=self.h,
                                      data=json.dumps({"type": "TXT", "name": name, "content": value, "ttl": 120})))
        return str((res or {}).get("id"))

    def delete(self, zone: str, rec: str) -> None:
        try:
            self.http.delete(f"{CLOUDFLARE_API}/zones/{zone}/dns_records/{rec}", headers=self.h)
        except Exception:  # noqa: BLE001 - a record left behind is harmless (a random TXT value); logged by the caller
            pass


# ── issue ───────────────────────────────────────────────────────────────
def _load_or_make_key(path: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import safe_files
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError):
        key = ec.generate_private_key(ec.SECP256R1())
        safe_files.write_private_atomic(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                serialization.NoEncryption()).decode("ascii"))
        return key


def issue(*, session=None, log=print) -> Dict[str, str]:
    """Get a certificate for ZSCALER_ACME_DOMAINS through dns-01, write it
    and its key to the TLS folder (owner-only), and return their paths."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import safe_files
    import server_tls
    names = domains()
    folder = server_tls.tls_dir()
    safe_files.private_makedirs(folder)
    http = _Http(session)
    acme = AcmeClient(_load_or_make_key(os.path.join(folder, ACCOUNT_KEY_FILE)), directory_url(), http)
    acme.register(os.environ.get("ZSCALER_ACME_EMAIL", "").strip()[:200])
    order_r = acme.post(acme.directory["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})
    order_url = acme._same_host(order_r.headers.get("Location"))
    order = _json(order_r)
    cf = Cloudflare(cloudflare_token(), http)
    made: List[Tuple[str, str]] = []
    try:
        pending = []
        for authz_url in order.get("authorizations") or []:
            authz = _json(acme.post(acme._same_host(authz_url), None))
            if authz.get("status") == "valid":
                continue
            ch = next((c for c in authz.get("challenges") or [] if isinstance(c, dict) and c.get("type") == "dns-01"), None)
            if not ch or not isinstance(ch.get("token"), str):
                raise AcmeError("The ACME server offered no dns-01 challenge.")
            name = str((authz.get("identifier") or {}).get("value") or "").lstrip("*.")
            if name not in [n.lstrip("*.") for n in names]:
                raise AcmeError("The ACME server asked about a name that was not ordered; stopped.")
            value = _b64u(hashlib.sha256(f"{ch['token']}.{acme.thumbprint()}".encode()).digest())
            zone = cf.zone_for(name)
            made.append((zone, cf.add_txt(zone, f"_acme-challenge.{name}", value)))
            pending.append((authz_url, acme._same_host(ch.get("url"))))
            log(f"  ACME: TXT record set for _acme-challenge.{name}")
        if pending:
            _sleep(max(0.0, min(600.0, float(os.environ.get("ZSCALER_ACME_DNS_WAIT", "30") or 30))))
        for authz_url, ch_url in pending:
            acme.post(ch_url, {})
            acme.poll(authz_url, ("valid",))
    finally:
        for zone, rec in made:
            cf.delete(zone, rec)
    cert_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
           .sign(cert_key, hashes.SHA256()))
    acme.post(acme._same_host(order.get("finalize")), {"csr": _b64u(csr.public_bytes(serialization.Encoding.DER))})
    order = acme.poll(order_url, ("valid",))
    chain_r = acme.post(acme._same_host(order.get("certificate")), None)
    pem = chain_r.content if isinstance(chain_r.content, bytes) else b""
    if not pem or len(pem) > MAX_RESPONSE:
        raise AcmeError("The ACME server gave no certificate.")
    certs = x509.load_pem_x509_certificates(pem)
    leaf = certs[0]
    if leaf.public_key().public_numbers() != cert_key.public_key().public_numbers():
        raise AcmeError("The certificate the ACME server gave is not for the key this server made; stopped.")
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if sorted(n.lower() for n in sans) != sorted(names):
        raise AcmeError("The certificate's names are not the ones ordered; stopped.")
    cert_path, key_path = os.path.join(folder, server_tls.CERT_FILE), os.path.join(folder, server_tls.KEY_FILE)
    safe_files.write_private_atomic(key_path, cert_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                      serialization.NoEncryption()).decode("ascii"))
    safe_files.write_private_atomic(cert_path, pem.decode("ascii"))
    try:
        import audit
        audit.record("acme_certificate_issued", actor="the app itself (no signed-in request)", names=names,
                     directory=urlparse(directory_url()).hostname, not_after=str(getattr(leaf, "not_valid_after_utc", "")))
    except Exception:  # noqa: BLE001
        pass
    return {"cert": cert_path, "key": key_path}


def ensure(*, session=None, log=print) -> Dict[str, Any]:
    """The ACME certificate to serve: the one in the TLS folder while it has
    more than RENEW_DAYS left, else a new one. A failed renewal keeps the
    old one while it is still valid (said on stderr)."""
    import server_tls
    folder = server_tls.tls_dir()
    cert, key = os.path.join(folder, server_tls.CERT_FILE), os.path.join(folder, server_tls.KEY_FILE)
    left = _days_left(cert) if os.path.isfile(cert) and os.path.isfile(key) else None
    if left is not None and left > RENEW_DAYS:
        return {"cert": cert, "key": key, "fingerprint": server_tls.fingerprint(cert), "self_signed": False, "generated": False, "acme": True}
    try:
        paths = issue(session=session, log=log)
        return {**paths, "fingerprint": server_tls.fingerprint(paths["cert"]), "self_signed": False, "generated": True, "acme": True}
    except Exception as e:  # noqa: BLE001
        if left is not None and left > 0:
            import sys
            print(f"  ACME renewal failed ({str(e)[:200]}); serving the current certificate, {left:.0f} day(s) left.", file=sys.stderr)
            return {"cert": cert, "key": key, "fingerprint": server_tls.fingerprint(cert), "self_signed": False, "generated": False, "acme": True}
        raise RuntimeError(f"Could not get a certificate through ACME: {e}") from None


def _days_left(cert_path: str) -> Optional[float]:
    try:
        from cryptography import x509
        with open(cert_path, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        end = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=_dt.timezone.utc)
        return (end - _dt.datetime.now(_dt.timezone.utc)).total_seconds() / 86400
    except (OSError, ValueError):
        return None


def _cli(argv: Optional[List[str]] = None) -> int:  # pragma: no cover - command line
    """python server_acme.py set-cloudflare-token | issue"""
    import getpass
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args == ["set-cloudflare-token"]:
            print(f"Kept in the {set_cloudflare_token(getpass.getpass('Cloudflare API token (Zone.DNS edit): '))}.")
        elif args == ["issue"]:
            out = issue()
            print(f"Certificate written to {out['cert']}.")
        else:
            print(_cli.__doc__)
            return 2
    except AcmeError as e:
        print(str(e))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
