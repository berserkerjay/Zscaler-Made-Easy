"""Path analyzer: "Test from here", an opt-in observation from the computer
running this app, compared with the analyzer's prediction.

The Path analyzer predicts from configuration. This module looks, once, at
what really happens to one destination from the machine the app runs on
(in the Docker container, the container's network): a DNS resolution, a
TCP connect and, for a TLS port, a TLS handshake (the certificate's issuer,
subject and names, the TLS version, whether this computer trusts it), then
compares that with the prediction ("predicted: inspected by ZIA; observed:
certificate issued by Zscaler Intermediate Root CA").

Threat model (this is an SSRF-sensitive feature; SECURITY.md has the same):

* Who can trigger it: only an authenticated viewer of this app (the UI
  token or an SSO session, the origin/CSRF check; every route has them),
  and only with an explicit click: the request must carry confirm=true.
  It can be switched off for a whole install with
  ZSCALER_TEST_FROM_HERE=0.
* What it can reach: one destination per request; its first resolved
  address is the only one connected to (pinned, so a second DNS answer
  cannot swap it, no DNS rebinding between check and connect). Refused
  before any packet: loopback (this computer and the app itself),
  link-local (169.254.0.0/16 and fe80::/10, which hold cloud metadata
  endpoints such as 169.254.169.254), multicast, unspecified (0.0.0.0, ::)
  and reserved addresses, IPv4-mapped forms of them included. Private
  addresses (RFC 1918, 100.64.0.0/10) are allowed on purpose: internal
  apps behind ZPA are what the analyzer is about, and a ZPA synthetic
  address (100.64.0.0/10) is itself an observation.
* Ports: an allow-list, ALLOWED_PORTS = 443, 80, 8443, 8080 (the web and
  TLS ports the analyzer's inspection prediction is about). A port the
  user typed is used only when it is in the list; any other port, even a
  valid 1-65535 one, is refused. Decision: allowing every typed port would
  turn this button into a one-port-per-click scanner of the networks the
  server sits on, which in the container or SSO deployment remote viewers
  could not otherwise reach; the four ports cover what the comparison
  needs (is TLS inspected, does the name resolve to a ZPA address).
* What it sends: a TCP connect, and on a TLS port a TLS ClientHello (with
  the host name as SNI). Never an HTTP request, a request body, a cookie,
  a credential or a client certificate; so there is nothing to redirect
  and no redirect is followed. The connection is closed right after the
  handshake. At most two TLS handshakes (one to read the certificate
  without trusting it, one to learn whether this computer trusts it).
* How long: DNS DNS_TIMEOUT, connect TCP_TIMEOUT and each handshake
  TLS_TIMEOUT seconds; the certificate is read up to MAX_CERT_BYTES.
* How often: at most RATE_PER_MINUTE probes a minute and one at a time
  for the whole server (429 otherwise).
* What is kept: nothing. The result goes back to the one viewer who
  asked, with Cache-Control no-store; it is never cached, shared between
  viewers or written to disk. The audit log records the call (who, the
  destination and port) like every other POST.
* Labelled: every result says it was observed "from the computer running
  this app" (or "from inside the app's Docker container"), not from the
  user's device the analysis is about.

Untrusted input: the destination goes through path_analyzer.
parse_destination (the analyzer's own parser); certificate fields are cut
to MAX_TEXT and shown as text only.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import socket
import ssl
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

ALLOWED_PORTS = (443, 80, 8443, 8080)
DNS_TIMEOUT = 3.0
TCP_TIMEOUT = 3.0
TLS_TIMEOUT = 4.0
RATE_PER_MINUTE = 6
MAX_CONCURRENT = 1
MAX_ADDRESSES = 8
MAX_CERT_BYTES = 64 * 1024
MAX_TEXT = 200
MAX_SANS = 20
# Tests only: the loopback test servers. Never set in the app.
ALLOW_LOOPBACK = False

ZPA_SYNTHETIC = ipaddress.ip_network("100.64.0.0/10")

_LOCK = threading.Lock()
_RECENT: Deque[float] = deque()
_BUSY = threading.BoundedSemaphore(MAX_CONCURRENT)
_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="zme-probe-dns")


class Refused(ValueError):
    """The request is not allowed (port, address, input): 400."""


class Busy(RuntimeError):
    """Too many probes just now: 429."""


def enabled() -> bool:
    """Off only when the install says so (ZSCALER_TEST_FROM_HERE=0)."""
    return os.environ.get("ZSCALER_TEST_FROM_HERE", "").strip().lower() not in ("0", "false", "no", "off")


def where() -> str:
    """Where the observation is made, in words."""
    if os.environ.get("DLP_CHECK_IN_CONTAINER", "").strip() == "1":
        return "from inside this app's Docker container (the container's network, not your computer's and not the user's device)"
    return "from the computer running this app (not the user's device the analysis is about)"


def _clip(v: Any, n: int = MAX_TEXT) -> str:
    return str(v if v is not None else "")[:n]


# ── What may be tested ───────────────────────────────────────────────
def choose_port(d: Dict[str, Any], typed: Any = None) -> int:
    """The port to test: the one typed (the Port field, else the URL's),
    which must be in ALLOWED_PORTS; otherwise 80 for http://, else 443."""
    p = typed if typed not in (None, "") else d.get("port")
    if p in (None, ""):
        return 80 if d.get("scheme") == "http" else 443
    try:
        n = int(str(p).strip())
    except (TypeError, ValueError):
        raise Refused("The port must be a whole number from 1 to 65535.")
    if not 1 <= n <= 65535:
        raise Refused("The port must be a whole number from 1 to 65535.")
    if n not in ALLOWED_PORTS:
        raise Refused(f"Test from here checks only ports {', '.join(map(str, ALLOWED_PORTS))} (web and TLS), so port {n} is not tested. "
                      "Nothing was sent.")
    return n


def address_refusal(ip: Any) -> Optional[str]:
    """Why an address may not be tested, or None."""
    a = ipaddress.ip_address(ip) if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip
    if getattr(a, "ipv4_mapped", None) is not None:
        a = a.ipv4_mapped
    if a.is_loopback and not ALLOW_LOOPBACK:
        return "it is this computer itself (a loopback address)"
    if a.is_link_local:
        return "it is a link-local address (where cloud metadata services live)"
    if a.is_multicast:
        return "it is a multicast address"
    if a.is_unspecified:
        return "it is the unspecified address"
    if a.version == 4 and a in ipaddress.ip_network("0.0.0.0/8"):
        return "it is a 'this network' address"
    if a.is_reserved:
        return "it is a reserved address"
    return None


# ── Rate limit ───────────────────────────────────────────────────────
def _take(now: float) -> None:
    with _LOCK:
        while _RECENT and now - _RECENT[0] >= 60.0:
            _RECENT.popleft()
        if len(_RECENT) >= RATE_PER_MINUTE:
            wait = int(60 - (now - _RECENT[0])) + 1
            raise Busy(f"Test from here runs at most {RATE_PER_MINUTE} times a minute; try again in {wait} seconds. Nothing was sent.")
        _RECENT.append(now)


def reset_rate_limit() -> None:
    """Tests: forget earlier probes."""
    with _LOCK:
        _RECENT.clear()


# ── The observation ──────────────────────────────────────────────────
def _resolve(host: str, port: int, timeout: float) -> List[str]:
    fut = _DNS_POOL.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    infos = fut.result(timeout=timeout)
    out: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out[:MAX_ADDRESSES]


def _name(name: Any, oid) -> Optional[str]:
    try:
        vals = name.get_attributes_for_oid(oid)
        return _clip(vals[0].value) if vals else None
    except Exception:  # noqa: BLE001
        return None


def parse_certificate(der: Optional[bytes]) -> Dict[str, Any]:
    """The leaf certificate's subject, issuer, names and validity, or
    "unknown" fields when it cannot be read. Never raises."""
    out: Dict[str, Any] = {"read": False, "subject_cn": None, "subject_o": None, "issuer_cn": None, "issuer_o": None, "sans": [],
                           "not_before": None, "not_after": None, "zscaler": None}
    if not der or len(der) > MAX_CERT_BYTES:
        return out
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
        c = x509.load_der_x509_certificate(der)
        out.update(read=True, subject_cn=_name(c.subject, NameOID.COMMON_NAME), subject_o=_name(c.subject, NameOID.ORGANIZATION_NAME),
                   issuer_cn=_name(c.issuer, NameOID.COMMON_NAME), issuer_o=_name(c.issuer, NameOID.ORGANIZATION_NAME))
        try:
            out["not_before"] = c.not_valid_before_utc.isoformat()
            out["not_after"] = c.not_valid_after_utc.isoformat()
        except Exception:  # noqa: BLE001
            pass
        try:
            san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = [_clip(n) for n in san.get_values_for_type(x509.DNSName)] + [_clip(str(n)) for n in san.get_values_for_type(x509.IPAddress)]
            out["sans"] = names[:MAX_SANS]
            out["sans_more"] = max(0, len(names) - MAX_SANS)
        except Exception:  # noqa: BLE001 — no SAN extension
            pass
    except Exception:  # noqa: BLE001 — not a certificate this can read: unknown, never a crash
        return out
    out["zscaler"] = is_zscaler_issuer(out.get("issuer_cn"), out.get("issuer_o"))
    return out


def is_zscaler_issuer(cn: Any, org: Any) -> bool:
    """Whether the issuer is a Zscaler inspection CA, by its name: ZIA's own
    inspection certificates are issued by "Zscaler Intermediate Root CA
    (...)" under organisation "Zscaler Inc." (assumed from Zscaler's help on
    the Zscaler root certificate; a tenant that signs with its own custom
    intermediate CA is not recognised by name and shows as "not Zscaler's
    name")."""
    return "zscaler" in f"{cn or ''} {org or ''}".lower()


def _tls(ip: str, port: int, host: Optional[str], verify: bool, timeout: float) -> Dict[str, Any]:
    """One TLS handshake to the pinned address. Sends a ClientHello only."""
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.monotonic()
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        # SNI is the host name; for an IP address typed as such, the
        # verifying check matches the address against the certificate.
        with ctx.wrap_socket(raw, server_hostname=host or (ip if verify else None), do_handshake_on_connect=True) as tls:
            ms = int((time.monotonic() - t0) * 1000)
            der = tls.getpeercert(binary_form=True)
            return {"version": tls.version(), "cipher": (tls.cipher() or [None])[0], "der": der, "ms": ms}


def observe(destination: str, port: Any = None, *, resolve: Optional[Callable[[str, int, float], List[str]]] = None) -> Dict[str, Any]:
    """DNS, TCP and (on a TLS port) TLS for one destination. Raises Refused
    for an input or address that may not be tested (before any packet for
    an address typed as such); network failures are part of the answer."""
    import path_analyzer
    try:
        d = path_analyzer.parse_destination(destination)
    except ValueError as e:
        raise Refused(str(e))
    port = choose_port(d, port)
    host = d["host"]
    tls_on = port != 80 and d.get("scheme") != "http"
    out: Dict[str, Any] = {"destination": d["input"], "host": host, "port": port, "where": where(), "at": time.time(),
                           "dns": {"ok": None, "addresses": [], "error": None, "how": ""},
                           "tcp": {"ok": None, "address": None, "ms": None, "error": None},
                           "tls": {"attempted": tls_on, "ok": None, "version": None, "cipher": None, "ms": None, "error": None,
                                   "trusted": None, "trust_error": None, "certificate": parse_certificate(None)},
                           "sent": "A TCP connect" + (" and a TLS handshake (ClientHello with the host name). " if tls_on else ". ")
                                   + "No HTTP request, body, cookie or credential; no redirect followed."}
    # 1. DNS
    if d["is_ip"]:
        addrs = [host]
        out["dns"].update(ok=True, addresses=addrs, how="An IP address was typed, so nothing was resolved.")
    else:
        try:
            addrs = (resolve or _resolve)(host, port, DNS_TIMEOUT)
        except concurrent.futures.TimeoutError:
            out["dns"].update(ok=False, error=f"No answer within {DNS_TIMEOUT:g} seconds.", how="This computer's resolver")
            return out
        except Exception as e:  # noqa: BLE001 — any resolver failure is an answer ("failed"), never a 500
            out["dns"].update(ok=False, error=_clip(getattr(e, "strerror", None) or type(e).__name__), how="This computer's resolver")
            return out
        out["dns"].update(ok=bool(addrs), addresses=addrs, how="This computer's resolver",
                          error=None if addrs else "The name resolved to no address.")
        if not addrs:
            return out
    ip = addrs[0]
    why = address_refusal(ip)
    if why:
        raise Refused(f"Test from here does not connect to {ip}: {why}. Nothing was sent to it.")
    out["dns"]["zpa_synthetic"] = any(ipaddress.ip_address(a) in ZPA_SYNTHETIC for a in addrs if ipaddress.ip_address(a).version == 4)
    # 2. TCP
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            pass
        out["tcp"].update(ok=True, address=ip, ms=int((time.monotonic() - t0) * 1000))
    except socket.timeout:
        out["tcp"].update(ok=False, address=ip, error=f"No answer within {TCP_TIMEOUT:g} seconds.")
        return out
    except OSError as e:
        out["tcp"].update(ok=False, address=ip, error=_clip(e.strerror or type(e).__name__))
        return out
    if not tls_on:
        return out
    # 3. TLS: read the certificate without trusting it, then ask whether this computer trusts it.
    sni = None if d["is_ip"] else host
    try:
        hs = _tls(ip, port, sni, False, TLS_TIMEOUT)
        out["tls"].update(ok=True, version=hs["version"], cipher=_clip(hs["cipher"], 80), ms=hs["ms"], certificate=parse_certificate(hs["der"]))
    except (ssl.SSLError, socket.timeout, OSError) as e:
        out["tls"].update(ok=False, error=_clip(getattr(e, "reason", None) or getattr(e, "strerror", None) or type(e).__name__))
        return out
    try:
        _tls(ip, port, sni, True, TLS_TIMEOUT)
        out["tls"]["trusted"] = True
    except ssl.SSLCertVerificationError as e:
        out["tls"].update(trusted=False, trust_error=_clip(e.verify_message or e.reason or "not trusted"))
    except (ssl.SSLError, socket.timeout, OSError, ValueError) as e:
        out["tls"].update(trusted=None, trust_error=_clip(getattr(e, "reason", None) or type(e).__name__))
    return out


# ── The prediction and the comparison ────────────────────────────────
def normalize_prediction(raw: Any) -> Optional[Dict[str, Any]]:
    """What the page sends of its result: bounded, known keys only."""
    if not isinstance(raw, dict) or not raw:
        return None

    def flag(v: Any) -> Optional[bool]:
        return v if isinstance(v, bool) else None
    return {"outcome": _clip(raw.get("outcome"), 40) or None, "headline": _clip(raw.get("headline"), 300) or None,
            "reaches_zscaler": flag(raw.get("reaches_zscaler")), "decrypted": flag(raw.get("decrypted")),
            "zpa": flag(raw.get("zpa")), "stops_at": _clip(raw.get("stops_at"), 120) or None}


def _issuer(cert: Dict[str, Any]) -> str:
    return cert.get("issuer_cn") or cert.get("issuer_o") or "an issuer this could not read"


def compare(pred: Optional[Dict[str, Any]], obs: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Each thing the prediction says that the observation can confirm or
    contradict: {topic, predicted, observed, agrees (True, False or None
    for cannot tell), note}."""
    out: List[Dict[str, Any]] = []
    tls, cert, dns, tcp = obs.get("tls") or {}, (obs.get("tls") or {}).get("certificate") or {}, obs.get("dns") or {}, obs.get("tcp") or {}
    if not pred:
        return [{"topic": "Prediction", "predicted": "none", "observed": "", "agrees": None,
                 "note": "Analyze the destination first to compare the observation with the analyzer's prediction."}]
    zs = cert.get("zscaler") if cert.get("read") else None
    seen_cert = (f"certificate issued by {_issuer(cert)}" if cert.get("read") else
                 "no certificate read" if tls.get("attempted") else "no TLS on this port")
    if pred.get("decrypted") is not None and tls.get("attempted"):
        p = "inspected by ZIA (decrypted)" if pred["decrypted"] else "not decrypted by ZIA"
        if zs is None:
            agrees, note = None, "The certificate could not be read, so whether ZIA decrypted it cannot be told."
        elif pred["decrypted"]:
            agrees = zs
            note = ("ZIA presented its own certificate: the connection from this computer was decrypted, as predicted." if zs else
                    "The certificate is not Zscaler's, so ZIA did not decrypt this computer's connection. This computer may not run Client Connector "
                    "or may use another profile, network or bypass than the one analyzed; or the tenant signs with its own CA (not recognised by name).")
        else:
            agrees = not zs
            note = ("The destination's own certificate came back: not decrypted, as predicted." if not zs else
                    "ZIA presented its own certificate, so this computer's connection was decrypted although the analysis predicts it is not: "
                    "this computer's profile, network or identity may differ from the one analyzed.")
        out.append({"topic": "SSL inspection", "predicted": p, "observed": seen_cert, "agrees": agrees, "note": note})
    if pred.get("reaches_zscaler") is False and zs is not None:
        out.append({"topic": "Reaches Zscaler", "predicted": "bypassed (goes direct)", "observed": seen_cert, "agrees": not zs,
                    "note": "A Zscaler certificate means the connection did reach ZIA." if zs else
                            "The destination's own certificate: consistent with a bypass (or a tunnel without decryption)."})
    if pred.get("zpa") is not None and dns.get("ok"):
        syn = bool(dns.get("zpa_synthetic"))
        out.append({"topic": "ZPA", "predicted": "carried by ZPA" if pred["zpa"] else "not carried by ZPA",
                    "observed": ("resolved to a ZPA synthetic address (100.64.0.0/10)" if syn else
                                 "resolved to " + ", ".join(dns.get("addresses") or [])[:120]),
                    "agrees": syn == pred["zpa"],
                    "note": ("Client Connector answered the name with a ZPA address, as it does for an application segment." if syn else
                             "Not a ZPA synthetic address: on this computer the name is not intercepted for ZPA (it may not run Client Connector with ZPA).")})
    if pred.get("outcome") == "blocked":
        out.append({"topic": "Block", "predicted": "blocked" + (f" at {pred['stops_at']}" if pred.get("stops_at") else ""),
                    "observed": "connected" if tcp.get("ok") else "no connection", "agrees": None,
                    "note": "ZIA usually blocks after the handshake (a block page or a reset of the request); this test sends no request, so it cannot see a block."})
    if tcp.get("ok") is False and pred.get("outcome") not in ("blocked", "zpa_denied"):
        out.append({"topic": "Reachable", "predicted": "reaches the destination", "observed": "no TCP connection: " + _clip(tcp.get("error"), 120),
                    "agrees": False, "note": "This computer could not connect; a firewall on its network or the destination itself may refuse it."})
    if not out:
        out.append({"topic": "Prediction", "predicted": pred.get("headline") or pred.get("outcome") or "", "observed": seen_cert, "agrees": None,
                    "note": "Nothing in this observation confirms or contradicts the prediction."})
    return out


def run(destination: str, port: Any = None, prediction: Any = None, *, now: Optional[float] = None,
        resolve: Optional[Callable[[str, int, float], List[str]]] = None) -> Dict[str, Any]:
    """The whole test for one request: rate limit and concurrency, the
    observation, the comparison. Raises Refused (400) or Busy (429)."""
    import path_analyzer
    try:   # bad input is refused before it counts against the limit
        choose_port(path_analyzer.parse_destination(destination), port)
    except ValueError as e:
        raise Refused(str(e))
    if not _BUSY.acquire(blocking=False):
        raise Busy("Another Test from here is running; try again in a few seconds. Nothing was sent.")
    try:
        _take(time.time() if now is None else now)
        obs = observe(destination, port, resolve=resolve)
    finally:
        _BUSY.release()
    pred = normalize_prediction(prediction)
    obs["tls"]["certificate"].pop("der", None)
    obs["comparison"] = compare(pred, obs)
    obs["prediction"] = pred
    return obs
