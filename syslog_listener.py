"""An optional syslog listener for ZIA NSS and ZPA LSS log lines (off by default).

Some customers send their NSS feed or LSS stream to a syslog receiver
rather than to files. This listener lets the admin point that stream at
this computer for a while, then analyse what arrived with the same reader
as an upload (traffic_logs.analyze).

Off by default: nothing listens until someone with the writer right starts
it from the Traffic and session logs page, and it stops when they stop it
or the server stops; it never starts on its own (the setting is not kept).

Where it listens: 127.0.0.1 (this computer only) unless the admin types
another address AND ticks "allow other computers" (allow_remote). The
address must be an IP address of this computer (not a host name); the
port is 1024 to 65535 (default 5514), UDP or TCP.

Caps (everything that arrives is untrusted):
  - MAX_MESSAGE bytes a message: a longer UDP datagram, or a TCP line that
    passes it before its newline, is dropped and counted (the rest of that
    TCP line is skipped up to its newline);
  - RATE_PER_SECOND messages a second with a burst of RATE_BURST (a token
    bucket over all senders): more is dropped and counted;
  - MAX_LINES lines and MAX_BUFFER_BYTES in memory: the oldest lines are
    dropped first and counted;
  - TCP: MAX_CONNECTIONS at once (more are closed at once), IDLE_SECONDS
    without data closes a connection.
Lines are decoded as UTF-8 (bad bytes replaced) and the syslog header is
taken off (RFC 3164 and RFC 5424 forms; strip_header) so traffic_logs reads
the NSS or LSS message itself. Nothing is parsed or interpreted on arrival.

Raw lines live in memory only and are never written to disk or logged.
"Analyze what arrived" makes a report like an upload (counts kept in the
server's memory); the admin may then save that report (counts only unless
they ask for names). "Clear" (and Stop with clear) forgets the lines.
"""
from __future__ import annotations

import collections
import ipaddress
import re
import select
import socket
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5514
PROTOCOLS = ("udp", "tcp")
MAX_MESSAGE = 8 * 1024
RATE_PER_SECOND = 500
RATE_BURST = 1000
MAX_LINES = 200_000
MAX_BUFFER_BYTES = 64 * 1024 * 1024
MAX_CONNECTIONS = 16
IDLE_SECONDS = 60.0
POLL_SECONDS = 0.5

_PRI = re.compile(r"\A<(\d{1,3})>")
_RFC5424 = re.compile(r"\A1 \S+ \S+ \S+ \S+ \S+ ")
_SD = re.compile(r"\A(?:-|(?:\[(?:[^\]\\]|\\.)*\])+) ?")
_RFC3164 = re.compile(r"\A[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ (?:[^\s:\[\]]{1,48}(?:\[\d{1,10}\])?: )?")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ListenerError(ValueError):
    """A setting or action the listener refuses; the message says why."""


def strip_header(line: str) -> str:
    """The message of one syslog line: the <PRI> and the RFC 5424 header
    (version, time, host, app, process, message id, structured data) or
    the RFC 3164 header (time, host, tag) taken off. A line without a
    header comes back as it is. Pure; never raises."""
    s = line
    m = _PRI.match(s)
    if m:
        s = s[m.end():]
    m = _RFC5424.match(s)
    if m:
        s = s[m.end():]
        sd = _SD.match(s)
        if sd:
            s = s[sd.end():]
        if s.startswith("\ufeff"):
            s = s[1:]
        return s
    m = _RFC3164.match(s)
    if m:
        s = s[m.end():]
    return s


def check_settings(host: Any = DEFAULT_HOST, port: Any = DEFAULT_PORT, protocol: Any = "udp", allow_remote: Any = False) -> Dict[str, Any]:
    """The address, port and protocol, checked (ListenerError says why)."""
    h = str(host or DEFAULT_HOST).strip()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        raise ListenerError("The address must be an IP address of this computer, like 127.0.0.1 (not a host name).") from None
    if ip.is_multicast:
        raise ListenerError("A multicast address cannot be listened on here.")
    if ip.is_unspecified and allow_remote is not True:
        raise ListenerError("Listening on every address (0.0.0.0 or ::) needs Allow other computers ticked.")
    if not ip.is_loopback and allow_remote is not True:
        raise ListenerError("Only this computer (127.0.0.1) can send unless you tick Allow other computers.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ListenerError("The port is a whole number from 1024 to 65535 (5514 is the usual unprivileged syslog port).")
    proto = str(protocol or "").strip().lower()
    if proto not in PROTOCOLS:
        raise ListenerError("The protocol is UDP or TCP.")
    return {"host": str(ip), "port": port, "protocol": proto, "allow_remote": allow_remote is True}


class _Bucket:
    """A token bucket: RATE_PER_SECOND tokens a second, at most RATE_BURST."""

    def __init__(self, rate: float = RATE_PER_SECOND, burst: float = RATE_BURST, clock=time.monotonic):
        self.rate, self.burst, self.clock = float(rate), float(burst), clock
        self.tokens, self.at = float(burst), clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class Listener:
    """One running listener and its in-memory buffer. feed() is the one
    place a message enters (tests call it directly)."""

    def __init__(self, settings: Dict[str, Any], *, rate: float = RATE_PER_SECOND, burst: float = RATE_BURST):
        self.settings = dict(settings)
        self.lines: Deque[str] = collections.deque()
        self.bytes = 0
        self.counts = {"received": 0, "kept": 0, "too_long": 0, "rate_limited": 0, "buffer_dropped": 0, "empty": 0,
                       "connections_refused": 0}
        self.senders: set = set()
        self.bucket = _Bucket(rate, burst)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self.sock: Optional[socket.socket] = None
        self.conns = 0
        self.started_at = time.time()
        self.bound: Tuple[str, int] = (self.settings["host"], self.settings["port"])

    # -- intake
    def feed(self, data: bytes, peer: str = "") -> bool:
        """One message (a datagram or a TCP line, without its newline)."""
        with self.lock:
            self.counts["received"] += 1
            if len(data) > MAX_MESSAGE:
                self.counts["too_long"] += 1
                return False
            if not self.bucket.take():
                self.counts["rate_limited"] += 1
                return False
            text = _CTRL.sub("", data.decode("utf-8", errors="replace")).strip("\r\n")
            msg = strip_header(text).strip()
            if not msg:
                self.counts["empty"] += 1
                return False
            if peer and len(self.senders) < 1000:
                self.senders.add(peer)
            self.lines.append(msg)
            self.bytes += len(msg)
            self.counts["kept"] += 1
            while len(self.lines) > MAX_LINES or self.bytes > MAX_BUFFER_BYTES:
                old = self.lines.popleft()
                self.bytes -= len(old)
                self.counts["buffer_dropped"] += 1
            return True

    def snapshot_text(self) -> str:
        with self.lock:
            return "\n".join(self.lines)

    def clear(self) -> None:
        with self.lock:
            self.lines.clear()
            self.bytes = 0

    def status(self) -> Dict[str, Any]:
        with self.lock:
            return {"running": not self.stop_event.is_set(), "host": self.bound[0], "port": self.bound[1],
                    "protocol": self.settings["protocol"], "allow_remote": self.settings.get("allow_remote", False),
                    "lines": len(self.lines), "bytes": self.bytes, "counts": dict(self.counts), "senders": len(self.senders),
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at))}

    # -- sockets
    def start(self) -> None:
        fam = socket.AF_INET6 if ":" in self.settings["host"] else socket.AF_INET
        kind = socket.SOCK_DGRAM if self.settings["protocol"] == "udp" else socket.SOCK_STREAM
        s = socket.socket(fam, kind)
        try:
            if kind == socket.SOCK_STREAM:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.settings["host"], self.settings["port"]))
            if kind == socket.SOCK_STREAM:
                s.listen(MAX_CONNECTIONS)
            s.settimeout(POLL_SECONDS)
        except OSError as e:
            s.close()
            raise ListenerError(f"Could not listen on {self.settings['host']} port {self.settings['port']} ({e.strerror or type(e).__name__}).") from None
        self.sock = s
        self.bound = s.getsockname()[:2]
        t = threading.Thread(target=self._udp_loop if kind == socket.SOCK_DGRAM else self._tcp_loop, name="syslog-listener", daemon=True)
        self.threads.append(t)
        t.start()

    def _udp_loop(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                data, peer = self.sock.recvfrom(MAX_MESSAGE + 1)
            except socket.timeout:
                continue
            except OSError:
                break
            self.feed(data, str(peer[0]))

    def _tcp_loop(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                full = self.conns >= MAX_CONNECTIONS
                if full:
                    self.counts["connections_refused"] += 1
                else:
                    self.conns += 1
            if full:
                conn.close()
                continue
            t = threading.Thread(target=self._tcp_conn, args=(conn, str(peer[0])), name="syslog-conn", daemon=True)
            t.start()

    def _tcp_conn(self, conn: socket.socket, peer: str) -> None:
        buf = bytearray()
        skipping = False
        last = time.monotonic()
        try:
            conn.setblocking(False)
            while not self.stop_event.is_set():
                ready, _w, _x = select.select([conn], [], [], POLL_SECONDS)
                if not ready:
                    if time.monotonic() - last > IDLE_SECONDS:
                        break
                    continue
                chunk = conn.recv(65536)
                if not chunk:
                    break
                last = time.monotonic()
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        if len(buf) > MAX_MESSAGE:   # a line past the cap: count it once, skip to its newline
                            if not skipping:
                                with self.lock:
                                    self.counts["received"] += 1
                                    self.counts["too_long"] += 1
                            skipping = True
                            buf.clear()
                        break
                    line = bytes(buf[:nl])
                    del buf[:nl + 1]
                    if skipping:
                        skipping = False
                        continue
                    self.feed(line, peer)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self.lock:
                self.conns -= 1

    def stop(self) -> None:
        self.stop_event.set()
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        for t in self.threads:
            t.join(timeout=2.0)


_CURRENT: Optional[Listener] = None
_GUARD = threading.Lock()


def current() -> Optional[Listener]:
    return _CURRENT


def start(host: Any = DEFAULT_HOST, port: Any = DEFAULT_PORT, protocol: Any = "udp", allow_remote: Any = False) -> Dict[str, Any]:
    """Start listening (one listener at a time). ListenerError when the
    settings are refused, one is already running, or the port is taken."""
    global _CURRENT
    s = check_settings(host, port, protocol, allow_remote)
    with _GUARD:
        if _CURRENT is not None and not _CURRENT.stop_event.is_set():
            raise ListenerError("The listener is already running; stop it first.")
        lst = Listener(s)
        lst.start()
        _CURRENT = lst
        return lst.status()


def stop(clear: bool = False) -> Dict[str, Any]:
    with _GUARD:
        lst = _CURRENT
        if lst is None:
            return {"running": False, "lines": 0}
        lst.stop()
        if clear:
            lst.clear()
        return lst.status()


def clear() -> Dict[str, Any]:
    lst = _CURRENT
    if lst is None:
        return {"running": False, "lines": 0}
    lst.clear()
    return lst.status()


def status() -> Dict[str, Any]:
    lst = _CURRENT
    base = {"defaults": {"host": DEFAULT_HOST, "port": DEFAULT_PORT, "protocol": "udp"},
            "limits": {"message_bytes": MAX_MESSAGE, "rate_per_second": RATE_PER_SECOND, "burst": RATE_BURST, "lines": MAX_LINES,
                       "buffer_mb": MAX_BUFFER_BYTES // (1024 * 1024), "connections": MAX_CONNECTIONS, "idle_seconds": int(IDLE_SECONDS)}}
    if lst is None:
        return dict(base, running=False, lines=0)
    return dict(base, **lst.status())


def buffered_upload() -> List[Dict[str, Any]]:
    """What arrived, as one upload for traffic_logs.analyze (in memory)."""
    lst = _CURRENT
    text = lst.snapshot_text() if lst is not None else ""
    if not text:
        raise ListenerError("Nothing has arrived yet.")
    return [{"name": "syslog.log", "content": text}]
