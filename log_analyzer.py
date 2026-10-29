"""Log Analyzer: Client Connector log bundles and PAC files, explained.

An engineer drops the files a customer sent (the ZIP that Client
Connector's *Export Logs* produces, single ZSATray / ZSATunnel / ZSAService
logs, a PAC file) and gets back, in plain English, what happened, what it
means for the user and what to do next. Everything runs in memory on the
local server: nothing is written to disk, nothing leaves the machine, and
the evidence lines shown back are redacted of anything that looks like a
secret.

Limits (a hostile archive must not exhaust the server): a bounded number of
members, a bounded size per member and in total (a .gz is streamed and
never inflated past the per-member cap; ZIP members only stored or
deflate, read in bounded steps; a compressed tar is read as one stream that
stops at the total cap, so skipping a member never inflates more), one
level of nesting, binary members skipped, member names never used as paths. Each line is read up to MAX_LINE_CHARS (a hostile single 10 MB line must not feed the
pattern matching), and every pattern that scans a run of characters for
an address starts only at the beginning of that run, so its cost grows
with the length of the text, never with its square.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import io
import lzma
import re
import tarfile
import zipfile
import zlib
from collections import Counter, deque
from typing import Any, Dict, List, Tuple

import safe_files

MAX_MEMBERS = 600
MAX_MEMBER_BYTES = 48 * 1024 * 1024
MAX_TOTAL_BYTES = 160 * 1024 * 1024
MAX_EVIDENCE = 4
EVIDENCE_WIDTH = 240
TOP_ERRORS = 6
MAX_LINE_CHARS = 4096   # a log or PAC line longer than this is read up to here
MAX_NOTES = 50          # notes about skipped members kept; the rest are counted

ARCHIVE_EXT = (".zip", ".tar", ".tgz", ".tar.gz", ".gz")
PAC_EXT = (".pac", ".dat", ".js")
LOG_EXT = (".log", ".txt", ".out", ".err")


# ── Redaction ────────────────────────────────────────────────────────
# A key names a credential when it ends in one of these words, whatever
# prefixes it (access_token, refresh-token, JSESSIONID, provisioning_key,
# "password" in JSON). Every key pattern starts only at the beginning of a
# run of key characters and its prefix is bounded, so a long run costs a
# linear scan.
_SECRET_WORDS = (r"password|passwd|passphrase|pwd|secret|token|bearer|api[_-]?key|apikey|session[_-]?id|sessionid|sessid"
                 r"|otp|provisioning[_-]?key|private[_-]?key|credentials?")
_SECRET_KV = re.compile(r"(?i)(?<![\w.-])([\"']?)([\w.-]{0,40}?(?:" + _SECRET_WORDS + r")[\w-]{0,20})\1(\s*[:=]\s*|\s+)"
                        r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;&}]+)")
# Authorization headers keep their scheme (Bearer, Basic...) and lose the value.
_AUTH_HEADER = re.compile(r"(?i)(?<![\w-])((?:proxy-)?authori[sz]ation)([\"']?\s*[:=]\s*[\"']?)(?:(bearer|basic|negotiate|ntlm|digest)\s+)?([^\s\"',;]+)")
# A cookie header carries many name=value pairs: everything after it goes.
_COOKIE_HEADER = re.compile(r"(?i)(?<![\w-])((?:set-)?cookie)(\s*[:=]\s*)\S.*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{48,}={0,2}\b")


def redact(line: str) -> str:
    """Drop anything that looks like a credential before a line is shown back."""
    s = _JWT.sub("[jwt-redacted]", line)
    s = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3) + ' ' if m.group(3) else ''}[redacted]", s)
    s = _COOKIE_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", s)
    s = _SECRET_KV.sub(lambda m: m.group(0) if m.group(4) == "[redacted]" else f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}[redacted]", s)
    s = _LONG_TOKEN.sub("[token-redacted]", s)
    if len(s) > EVIDENCE_WIDTH:
        s = s[:EVIDENCE_WIDTH - 1] + "…"
    return s


# ── Unpacking ────────────────────────────────────────────────────────
def _decode_upload(f: Dict[str, Any]) -> bytes:
    content = f.get("content") or ""
    if (f.get("encoding") or "").lower() == "base64":
        try:
            return base64.b64decode(content, validate=False)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"{f.get('name') or 'file'}: not valid base64 ({e})")
    return content.encode("utf-8", errors="replace")


def _basename(name: str) -> str:
    name = (name or "").replace("\\", "/")
    return name.rsplit("/", 1)[-1] or "file"


def _is_binary(data: bytes) -> bool:
    head = data[:4096]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False   # UTF-16 text with a BOM
    return b"\x00" in head


def _to_text(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


class _NoteList(list):
    """The notes about what was skipped, at most MAX_NOTES of them: an
    archive of a hundred thousand entries must not come back as a hundred
    thousand notes. The rest are counted in one closing note."""

    def __init__(self) -> None:
        super().__init__()
        self.dropped = 0

    def append(self, note: str) -> None:  # type: ignore[override]
        if len(self) < MAX_NOTES:
            super().append(note)
        else:
            self.dropped += 1

    def closed(self) -> List[str]:
        return list(self) + ([f"… and {self.dropped} more notes like these"] if self.dropped else [])


class _Budget:
    def __init__(self) -> None:
        self.members = 0
        self.total = 0
        self.full = False
        self.notes = _NoteList()

    def take(self, name: str, size: int) -> bool:
        if self.members >= MAX_MEMBERS:
            if not self.full:
                self.notes.append(f"stopped after {MAX_MEMBERS} files; the rest of the archive was not read")
            self.full = True
            return False
        if size > MAX_MEMBER_BYTES:
            self.notes.append(f"{name}: skipped, larger than {MAX_MEMBER_BYTES // (1024 * 1024)} MB")
            return False
        if self.total + size > MAX_TOTAL_BYTES:
            self.notes.append(f"{name}: skipped, the archive expands past {MAX_TOTAL_BYTES // (1024 * 1024)} MB in total")
            return False
        self.members += 1
        self.total += size
        return True


_TAR_SLACK = 1024 * 1024   # headers and padding around the members the budget allows


class _CappedReader(io.RawIOBase):
    """A read-only stream that ends after `cap` bytes and remembers that it did."""

    def __init__(self, raw: Any, cap: int) -> None:
        super().__init__()
        self._raw, self._left, self.capped = raw, cap, False

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self._left <= 0:
            self.capped = self.capped or bool(self._raw.read(1))
            return 0
        n = min(len(b), self._left)
        chunk = self._raw.read(n)
        b[:len(chunk)] = chunk
        self._left -= len(chunk)
        return len(chunk)


def _decompressed(data: bytes) -> Any:
    """A reader of `data` as a tar stream: gzip, bzip2 and xz are inflated
    as they are read (bounded by the caller), anything else as it is."""
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=io.BytesIO(data))
    if data[:3] == b"BZh":
        return bz2.BZ2File(io.BytesIO(data))
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(io.BytesIO(data))
    return io.BytesIO(data)


def expand(files: List[Dict[str, Any]]) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """[(name, bytes)] for every readable member of every upload, and notes
    about what was skipped. Archives are opened one level deep."""
    out: List[Tuple[str, bytes]] = []
    budget = _Budget()
    for f in files:
        name = _basename(str(f.get("name") or "file"))
        data = _decode_upload(f)
        _expand_one(name, data, out, budget, depth=0)
    return out, budget.notes.closed()


def _expand_one(name: str, data: bytes, out: List[Tuple[str, bytes]], budget: _Budget, depth: int) -> None:
    low = name.lower()
    if low.endswith(".zip") or (data[:4] == b"PK\x03\x04" and not low.endswith(LOG_EXT + PAC_EXT)):
        if depth > 1:
            budget.notes.append(f"{name}: nested archive not opened (one level only)")
            return
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if budget.full:
                        break
                    if info.is_dir():
                        continue
                    member = _basename(info.filename)
                    if not budget.take(member, info.file_size):
                        continue
                    try:
                        payload = safe_files.zip_member(z, info, MAX_MEMBER_BYTES)
                    except safe_files.ArchiveRefused as e:
                        budget.notes.append(f"{member}: skipped, {str(e).split(': ', 1)[-1]}")
                        continue
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as e:
                        budget.notes.append(f"{member}: could not be read ({e})")
                        continue
                    _expand_one(member, payload, out, budget, depth + 1)
        except zipfile.BadZipFile:
            budget.notes.append(f"{name}: not a valid ZIP file")
        return
    if low.endswith((".tar", ".tgz", ".tar.gz")) or (len(data) > 262 and data[257:262] == b"ustar"):
        if depth > 1:
            budget.notes.append(f"{name}: nested archive not opened (one level only)")
            return
        # One forward pass over the (decompressed) stream, which stops at the
        # total cap: skipping a member, or a long-name / pax header, would
        # otherwise inflate whatever size its header claims.
        stream = _CappedReader(_decompressed(data), MAX_TOTAL_BYTES + _TAR_SLACK)
        try:
            with tarfile.open(fileobj=stream, mode="r|") as t:
                for info in t:
                    if budget.full or (budget.members >= MAX_MEMBERS and not budget.take(info.name, 0)):
                        break
                    if not info.isfile():
                        continue
                    member = _basename(info.name)
                    if not budget.take(member, info.size):
                        continue
                    fh = t.extractfile(info)
                    if fh is None:
                        continue
                    _expand_one(member, fh.read(MAX_MEMBER_BYTES + 1), out, budget, depth + 1)
        except (tarfile.TarError, OSError, EOFError, lzma.LZMAError) as e:
            if not stream.capped:
                budget.notes.append(f"{name}: not a valid tar archive ({e})")
        if stream.capped:
            budget.notes.append(f"{name}: stopped after {MAX_TOTAL_BYTES // (1024 * 1024)} MB of the unpacked archive; the rest was not read")
        return
    if low.endswith(".gz"):
        if depth > 1:
            budget.notes.append(f"{name}: nested archive not opened (one level only)")
            return
        # Stream the output and stop one byte past the cap: a small .gz can
        # inflate to gigabytes, so the whole member is never unpacked first.
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
                inner = g.read(MAX_MEMBER_BYTES + 1)
        except (OSError, EOFError, zlib.error) as e:   # zlib.error: a damaged deflate stream behind a good header
            budget.notes.append(f"{name}: could not gunzip ({e})")
            return
        if len(inner) > MAX_MEMBER_BYTES:
            budget.notes.append(f"{name}: skipped, larger than {MAX_MEMBER_BYTES // (1024 * 1024)} MB once unpacked")
            return
        if not budget.take(name[:-3], len(inner)):
            return
        _expand_one(name[:-3], inner, out, budget, depth + 1)
        return
    if depth == 0 and not budget.take(name, len(data)):
        return
    if _is_binary(data):
        budget.notes.append(f"{name}: skipped (binary file)")
        return
    out.append((name, data))


# ── Classification ───────────────────────────────────────────────────
_PAC_MARK = re.compile(r"function\s+FindProxyForURL\s*\(", re.I)


def kind_of(name: str, text: str) -> str:
    low = name.lower()
    if _PAC_MARK.search(text[:200000]):
        return "pac"
    if low.endswith(PAC_EXT):
        return "pac"
    return "log"


# ── Line parsing ─────────────────────────────────────────────────────
_TS_ISO = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?")
_TS_US = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{2}:\d{2}:\d{2})")
_TS_SYSLOG = re.compile(r"^\s*(?:\w{3}\s+)?(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
_LEVEL = re.compile(r"\b(DBG|DEBUG|INF|INFO|WRN|WARN|WARNING|ERR|ERROR|CRIT|CRITICAL|FATAL|FTL)\b")
_LEVEL_MAP = {"DBG": "debug", "DEBUG": "debug", "INF": "info", "INFO": "info", "WRN": "warn", "WARN": "warn", "WARNING": "warn",
              "ERR": "error", "ERROR": "error", "CRIT": "error", "CRITICAL": "error", "FATAL": "error", "FTL": "error"}
_MONTHS = {m: i + 1 for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_line(line: str) -> Dict[str, Any]:
    """{ts, level, msg}: ts is an ISO-like string or '' (syslog lines have no year)."""
    ts = ""
    m = _TS_ISO.match(line)
    if m:
        ts = f"{m.group(1)} {m.group(2)}"
    else:
        m = _TS_US.match(line)
        if m:
            ts = f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d} {m.group(4)}"
        else:
            m = _TS_SYSLOG.match(line)
            if m:
                ts = f"????-{_MONTHS[m.group(1)]:02d}-{int(m.group(2)):02d} {m.group(3)}"
    head = line[:96]
    lm = _LEVEL.search(head)
    level = _LEVEL_MAP.get(lm.group(1), "") if lm else ""
    return {"ts": ts, "level": level, "msg": line.strip()}


# ── Signature catalogue ──────────────────────────────────────────────
# Each signature is one story an engineer needs to recognise. `pattern`
# runs on the whole line (case-insensitive). `min_count` keeps single
# transient events from becoming a finding. `severity` says how much the
# user is affected right now: critical (not protected / cannot work),
# high (protection degraded), medium (worth fixing), info (context that
# explains the others).
SIGNATURES: List[Dict[str, Any]] = [
    {
        "key": "captive_portal", "severity": "info", "min_count": 1,
        "pattern": r"captive\s*portal",
        "title": "The device was behind a captive portal (hotel, airport or guest Wi-Fi sign-in page)",
        "what": "Client Connector detected a network that wants the user to sign in on a web page before it allows any other traffic.",
        "means": "Until the user completes that sign-in page nothing can reach Zscaler, so every tunnel and sign-in error in the same minutes is expected, not a fault. Client Connector pauses (captive portal detection) so the user can reach the page.",
        "do": ["Ask the user to open the browser and finish the Wi-Fi sign-in page, then wait 30 seconds.",
               "If it stays stuck, check the Client Connector Forwarding Profile: Captive Portal Detection should be on, with a sensible detection window.",
               "Compare the timestamps: errors only while behind the portal need no fix."],
    },
    {
        "key": "trusted_network", "severity": "info", "min_count": 1,
        "pattern": r"trusted\s*network.{0,60}\b(detected|matched|found|on trusted|is trusted|criteria met)\b",
        "title": "The device was on a trusted network (an office or VPN the customer defined)",
        "what": "Client Connector matched the trusted-network criteria in the Forwarding Profile (DNS server, DNS search domain, hostname/IP or predefined trusted network).",
        "means": "On a trusted network the Forwarding Profile decides what happens: Zscaler traffic may be intentionally sent through the customer's own proxy or not tunnelled at all. If the customer says 'Zscaler is off in the office', this is usually why, by design.",
        "do": ["Open ZCC Admin Portal > Administration > Forwarding Profile and read the On Trusted Network settings for this user's profile.",
               "If the customer wants Zscaler protection in the office too, the trusted-network action should be Tunnel, not None.",
               "If a home network is being detected as trusted, the criteria are too loose (for example a common DNS server)."],
    },
    {
        "key": "vpn_detected", "severity": "info", "min_count": 1,
        "pattern": r"\bvpn\b.{0,40}\b(detected|found|adapter|interface|active|connected)\b|\b(detected|found)\b.{0,40}\bvpn\b",
        "title": "A third-party VPN was active on the device",
        "what": "Client Connector saw a VPN adapter or a VPN network in use.",
        "means": "Two tunnels on one device compete for traffic. Depending on the Forwarding Profile's VPN-trusted-network settings, Zscaler either tunnels inside the VPN, bypasses it, or the VPN wins and Zscaler sees nothing (a data-loss blind spot).",
        "do": ["Ask which VPN and whether it is expected; ZPA is meant to replace remote-access VPNs.",
               "Check the Forwarding Profile's Trusted Network / VPN Trusted Network criteria and the app profile's VPN gateway bypass list.",
               "If users must keep the VPN, make sure the VPN's own bypass list sends Zscaler's cloud addresses outside the VPN."],
    },
    {
        "key": "auth_failed", "severity": "critical", "min_count": 1,
        "pattern": r"(auth\w*|login|sign[- ]?in|saml|idp|token)\W.{0,80}\b(fail\w*|denied|invalid|rejected|unauthori[sz]ed|expired|error)\b|\b(fail\w*|denied|invalid|rejected|unauthori[sz]ed)\b.{0,60}\b(auth\w*|login|sign[- ]?in|saml|idp)\b|http.{0,10}\b40[13]\b",
        "exclude": r"captive|posture",
        "title": "Signing the user in to Zscaler failed",
        "what": "Client Connector could not complete the user's sign-in (the identity provider redirect, the SAML response or the token refresh was refused).",
        "means": "An unsigned-in Client Connector does not protect the device at all: web traffic goes straight out, no DLP, no URL filtering, no ZPA access.",
        "do": ["Ask the user to sign out of Client Connector and sign in again; watch whether the IdP page appears at all.",
               "If the IdP page never appears: the IdP or Zscaler login domain is unreachable (see any DNS, proxy or captive-portal findings here).",
               "If the IdP accepts the password but Zscaler refuses: the user may not be provisioned in ZIA/ZIdentity (SCIM or the user database) or the SAML assertion's NameID does not match the user's email.",
               "Check ZIdentity > Users for the account, and the Authentication settings for the IdP certificate expiry."],
    },
    {
        "key": "pac_download", "severity": "high", "min_count": 1,
        "pattern": r"\bpac\b.{0,60}\b(fail\w*|error|timeout|timed out|unreachable|could not|cannot|unable)\b|\b(fail\w*|error|unable|cannot)\b.{0,40}\bpac\b",
        "title": "The PAC file could not be downloaded",
        "what": "Client Connector (or the browser) could not fetch the PAC file that tells the device where to send web traffic.",
        "means": "Without the PAC the app profile falls back to its default, and traffic may go direct (unprotected) or nowhere. It is one of the most common causes of 'the internet stopped working when Zscaler turned on'.",
        "do": ["Open the PAC URL from the ZCC Admin Portal app profile in a browser on the device; it must download as plain text.",
               "If it fails only on some networks, something in that network (a firewall, another proxy) blocks pac.<cloud>.net; whitelist Zscaler's PAC hosts.",
               "If the PAC is custom-hosted, check that host's certificate and availability.",
               "Drop the PAC file itself into this analyzer to check its contents."],
    },
    {
        "key": "cert_error", "severity": "high", "min_count": 1,
        "pattern": r"(certificate|cert|ssl|tls)\W.{0,60}\b(invalid|untrusted|verif\w+ fail\w*|expired|self[- ]signed|unknown (ca|issuer)|not trusted|revoked|chain|handshake fail\w*|error)\b",
        "exclude": r"pinning|installed successfully|cert(ificate)? added",
        "title": "A certificate or TLS handshake was rejected",
        "what": "A TLS connection from the client (to the Zscaler cloud, the PAC host, the identity provider or an update server) failed certificate validation.",
        "means": "Usually a device in the middle: a corporate proxy or firewall that inspects TLS and re-signs it with its own root, which Client Connector does not trust. The client then cannot reach the cloud and the user is unprotected or blocked.",
        "do": ["Find out whether the network has a TLS-inspecting proxy or firewall; ask it to exempt Zscaler's cloud, PAC and login domains from inspection.",
               "If the customer deliberately inspects, the inspecting root must be installed in the machine store and trusted by the client.",
               "Check the device clock: a clock hours out makes every certificate look expired.",
               "If the error names the Zscaler root, reinstall Client Connector so the Zscaler root certificate is restored."],
    },
    {
        "key": "dns_failed", "severity": "high", "min_count": 2,
        "pattern": r"\bdns\b.{0,60}\b(fail\w*|error|unable|cannot|could not|nxdomain|timeout|timed out|no such host|not resolv\w+)\b|\b(resolv\w+|lookup)\b.{0,30}\b(fail\w*|error)\b|could not resolve",
        "title": "Name lookups (DNS) were failing",
        "what": "The client could not resolve host names, including the Zscaler gateway or login hosts, into addresses.",
        "means": "Nothing works without DNS: no sign-in, no tunnel, no PAC. When this appears together with a captive-portal or network-change finding it is transient; on its own it points at the network's DNS server or a DNS security product blocking the lookups.",
        "do": ["On the device, run nslookup gateway.<cloud>.net and the login host; both must resolve on this network.",
               "If a DNS filtering product is in place, allow Zscaler's domains.",
               "For ZPA, check whether the ZPA DNS interception is interfering with the customer's own resolvers (app segment domains)."],
    },
    {
        "key": "tunnel_down", "severity": "critical", "min_count": 2,
        "pattern": r"tunnel.{0,60}\b(down|fail\w*|disconnect\w*|dropped|broken|lost|error|closed unexpectedly|could not establish|unable to establish|not established|reconnect\w*)\b|tunnel_state_\w*(off|down|fail|disconnect)\w*",
        "exclude": r"tunnel\s*2\.0.{0,40}(fallback|falling back)|reconnect\w* successfully",
        "title": "The Zscaler tunnel went down or could not be established",
        "what": "The tunnel that carries the user's traffic to the Zscaler cloud (Z-Tunnel 1.0 or 2.0) failed or dropped.",
        "means": "While the tunnel is down the device is either unprotected (fail open) or without internet (fail close), whichever the Forwarding Profile says. Repeated drops mean an unstable path to the cloud: a firewall closing idle UDP, a network change, or the cloud data centre unreachable.",
        "do": ["Read the surrounding lines for the reason: network change, DTLS/TLS handshake, keepalive timeout, or gateway unreachable.",
               "Check the firewall allows outbound UDP 443 (Z-Tunnel 2.0 DTLS) and TCP 443/80 to the Zscaler cloud ranges; long idle timeouts.",
               "If the drops line up with Wi-Fi roaming or sleep/resume, they are expected and the client should recover within seconds.",
               "If a Zscaler data centre is named, check trust.zscaler.com for an incident at that DC."],
    },
    {
        "key": "tunnel2_fallback", "severity": "medium", "min_count": 1,
        "pattern": r"(tunnel\s*2\.0|ztunnel2|dtls).{0,80}\b(fallback|falling back|fall back|blocked|fail\w*|not (allowed|available|supported))\b|\bfall(ing)? back to (tunnel|z-?tunnel)\s*1\.0",
        "title": "Z-Tunnel 2.0 was blocked and the client fell back to Z-Tunnel 1.0",
        "what": "The DTLS/TLS tunnel (Z-Tunnel 2.0) could not be built on this network, so the client fell back to the older HTTP-CONNECT tunnel (Z-Tunnel 1.0) if the profile allows it.",
        "means": "Z-Tunnel 1.0 carries only web ports (80/443). Non-web traffic and the Cloud Firewall, plus parts of DLP visibility, are lost while fallback lasts. The customer's firewall is almost always the cause: outbound UDP 443 blocked.",
        "do": ["Ask the network team to allow outbound UDP 443 to the Zscaler cloud; if UDP cannot be opened, allow TCP 443 so Z-Tunnel 2.0 over TLS works.",
               "In the Forwarding Profile, check the Z-Tunnel 2.0 settings and whether fallback to 1.0 is intended.",
               "Verify with the user after the change: the ZCC tray should show Z-Tunnel 2.0."],
    },
    {
        "key": "gateway_unreachable", "severity": "high", "min_count": 2,
        "pattern": r"(gateway|cloud|zscaler|zen|service edge|broker|data ?cent(er|re))\W.{0,60}\b(unreachable|timed? ?out|timeout|no response|connection (refused|reset)|not reachable|down|fail\w* to connect|could not connect|unable to connect)\b|\b(connect\w*|request)\b.{0,40}\b(timed? ?out|timeout)\b",
        "exclude": r"captive",
        "title": "The Zscaler cloud (gateway or service edge) did not answer",
        "what": "Connections from the client to a Zscaler gateway, a ZPA Service Edge or the cloud's control services timed out or were refused.",
        "means": "The client is on a network that does not let it reach the cloud, or the cloud endpoint it was given is unhealthy. Users see slow or no internet, or ZPA apps that never load.",
        "do": ["Check the firewall and any upstream proxy: Zscaler's published IP ranges (config.zscaler.com) must be reachable on TCP 80/443 and UDP 443.",
               "From the device, test with the ZCC tray's connectivity check (Zscaler icon > More > Troubleshoot).",
               "Look at trust.zscaler.com for the named data centre; a 'gateway unreachable' burst across many users at once is usually a cloud or ISP incident."],
    },
    {
        "key": "proxy_auth", "severity": "high", "min_count": 1,
        "pattern": r"\b407\b|proxy.{0,40}\b(auth\w*|credential\w*)\b.{0,30}\b(required|fail\w*|denied)\b|proxy authentication required",
        "title": "A proxy in the path demands its own authentication",
        "what": "Something between the device and the internet answered 407 Proxy Authentication Required.",
        "means": "Client Connector cannot answer a proxy's login prompt, so nothing gets out. This is the customer's legacy proxy still in the path, usually via a system proxy setting, a GPO or a WPAD/PAC that points at it.",
        "do": ["Find the proxy (Windows: netsh winhttp show proxy, the browser's proxy settings, the GPO) and remove it from the path, or add Zscaler's destinations to its no-auth allow list.",
               "If the customer must keep the proxy for now, configure it as the ZCC Forwarding Profile's proxy (with the credentials there), not as a system proxy."],
    },
    {
        "key": "zpa_failed", "severity": "high", "min_count": 1,
        "pattern": r"\bzpa\b.{0,60}\b(fail\w*|error|unreachable|disabled|denied|no (broker|service edge)|cannot|unable|timeout|timed out)\b|(broker|service edge|app connector).{0,40}\b(unreachable|fail\w*|error|not available)\b",
        "exclude": r"posture",
        "title": "Zscaler Private Access (ZPA) could not connect",
        "what": "The client could not reach a ZPA Service Edge (broker) or its ZPA session failed.",
        "means": "The user's private applications (intranet, file shares, RDP through ZPA) will not open, even if internet browsing through ZIA works.",
        "do": ["Check the ZCC tray: Private Access must show ON; if it says OFF or 'disabled by policy', the user is not in a ZPA policy or the app profile disables ZPA.",
               "Allow outbound TCP 443 to the ZPA Service Edge addresses; some firewalls block them while allowing ZIA.",
               "In the ZPA Admin Portal, check the user's access policy and that an App Connector for the segment is healthy."],
    },
    {
        "key": "posture_failed", "severity": "medium", "min_count": 1,
        "pattern": r"posture.{0,60}\b(fail\w*|not met|not compliant|mismatch|denied|false)\b",
        "title": "A device posture check did not pass",
        "what": "One of the ZPA posture profiles (disk encryption, domain joined, certificate, OS version, running process, firewall on, and so on) evaluated false on this device.",
        "means": "Access policies that require that posture will deny the user those private applications. Nothing is broken; the device does not meet the customer's rule.",
        "do": ["Find which posture profile failed (the line names it) and check that condition on the device.",
               "If the device should pass, compare the posture profile's definition (for example the expected certificate issuer or the process name) with what the device actually has."],
    },
    {
        "key": "network_change", "severity": "info", "min_count": 3,
        "pattern": r"network (change|changed|switch\w*)|nic (change|changed)|interface (change|changed|added|removed)|ip (address )?(change|changed)|\b(sleep|resume|hibernat\w*|wake)\b.{0,40}\b(event|detected|state)\b",
        "title": "The device changed networks or woke from sleep several times",
        "what": "Client Connector rebuilt its tunnel because the network changed (Wi-Fi roaming, docking, VPN up/down, sleep and resume).",
        "means": "Each change causes a short reconnection; errors within a few seconds of a change are normal. Many changes in a short period point at flapping Wi-Fi or a VPN that keeps reconnecting.",
        "do": ["Compare the timestamps of tunnel errors with these events; only errors that persist after a change need attention.",
               "If the device flaps between Wi-Fi and Ethernet, ask the user to disable one while docked."],
    },
    {
        "key": "update_failed", "severity": "medium", "min_count": 1,
        "pattern": r"(update|upgrade|download|installer|msi|pkg).{0,60}\b(fail\w*|error|checksum|signature|corrupt\w*|could not|cannot|unable|rolled back)\b",
        "exclude": r"pac|policy|config",
        "title": "A Client Connector update failed",
        "what": "The auto-update (or the download or the signature check of the new build) did not complete.",
        "means": "The user stays on the old version. An outdated client misses fixes and may not support features the admin turned on, but protection continues on the installed version.",
        "do": ["Check the ZCC Admin Portal app profile's Client Connector version assignment and the update interval.",
               "If the download fails, the update servers (the Zscaler cloud's update host) are blocked by a firewall or proxy; allow them.",
               "If installation fails, install the package manually once (as an administrator) and watch the installer log."],
    },
    {
        "key": "config_failed", "severity": "high", "min_count": 1,
        "pattern": r"(policy|config\w*|app ?profile|forwarding ?profile|settings)\W.{0,60}\b(download|fetch|retriev\w+|load\w*|sync\w*)\b.{0,40}\b(fail\w*|error|timeout|timed out|unable|cannot|could not)\b|fail\w* to (download|fetch|get|load) (the )?(policy|config\w*|app ?profile)",
        "title": "The client could not download its policy or app profile",
        "what": "Client Connector could not fetch its configuration (app profile, forwarding profile, PAC assignments, bypass lists) from the cloud.",
        "means": "The client keeps running on the last configuration it had. Changes the admin makes in the portal do not reach this device, so 'we changed the bypass but it still does not work' is explained here.",
        "do": ["Check the same causes as a gateway or DNS failure: the cloud must be reachable.",
               "Ask the user to click Update Policy in the Client Connector tray (More > Update Policy) and watch for a new error.",
               "If only this device fails, its enrolment may be stale: sign out and sign in again re-enrols it."],
    },
    {
        "key": "disabled_by_user", "severity": "critical", "min_count": 1,
        "pattern": r"(disabled?|turn\w* off|stop\w*|exit\w*|uninstall\w*)\b.{0,40}\b(by (the )?user|by admin|via password|with password|service|zscaler service)\b|service (is )?(stopped|not running)|(user|admin) (disabled|turned off)|logout password|disable password",
        "exclude": r"posture|policy",
        "title": "Client Connector was turned off, stopped or uninstalled",
        "what": "The service or the app was disabled, exited or uninstalled (with or without the admin password).",
        "means": "While off, the device has no Zscaler protection at all; this is the single biggest data-loss blind spot on an endpoint. If the user did it without a password, the app profile does not require one.",
        "do": ["Check the ZCC Admin Portal app profile: Disable Password, Logout Password, Uninstall Password and 'Enable Tamper Protection' should be set for managed devices.",
               "Ask why the user turned it off; the reason is usually a connectivity problem this analyzer also lists.",
               "Confirm the service is running now (Windows: Zscaler App service; macOS: the Zscaler menu-bar icon)."],
    },
    {
        "key": "driver_error", "severity": "high", "min_count": 1,
        "pattern": r"(wfp|filter driver|packet filter|network extension|kext|system extension|tun(nel)? (adapter|interface)|route (add|delete)|firewall rule|callout)\W.{0,60}\b(fail\w*|error|not loaded|could not|cannot|unable|denied|blocked|missing)\b",
        "title": "The network driver or system extension did not load",
        "what": "The Windows Filtering Platform driver, the macOS network/system extension or the tunnel adapter that Client Connector uses to capture traffic could not be installed, loaded or configured.",
        "means": "Without the driver the client cannot intercept traffic: it looks signed in but nothing is tunnelled (packet-filter mode) or the tunnel adapter is missing. On macOS the user usually has to approve the extension once.",
        "do": ["macOS: System Settings > Privacy & Security must show the Zscaler network extension allowed; MDM can pre-approve it (a PPPC / system extension profile).",
               "Windows: reinstall Client Connector as an administrator; check whether another security agent's driver conflicts (the line often names it).",
               "Check the device's Client Connector event in the ZCC Admin Portal > Enrolled Devices for the last reported state."],
    },
    {
        "key": "crash", "severity": "high", "min_count": 1,
        "pattern": r"\b(unhandled exception|access violation|segmentation fault|segfault|stack ?trace|crash(ed|ing)?|abnormal termination|fatal error|core dump)\b",
        "title": "A Client Connector process crashed",
        "what": "One of the client's processes (tray, tunnel, service or updater) hit a fatal error.",
        "means": "The service restarts automatically in most cases, with a short gap in protection. Repeated crashes on one version are a product defect to raise with Zscaler Support with these logs attached.",
        "do": ["Note the process and version on the lines around it.",
               "Check whether the crashes coincide with another agent (EDR, another VPN) starting.",
               "Open a Zscaler Support case with the exported log bundle; include the exact time of the crash."],
    },
    {
        "key": "strict_enforcement", "severity": "info", "min_count": 1,
        "pattern": r"strict enforcement",
        "title": "Strict Enforcement is on: the device blocks internet until the user signs in",
        "what": "The app profile has Strict Enforcement enabled, which blocks all traffic until Client Connector is signed in and protecting the device.",
        "means": "This is what 'no internet until I log in to Zscaler' means; it is intentional and the secure setting. Any sign-in problem then looks like a total outage to the user.",
        "do": ["Nothing to fix by itself. Resolve any sign-in, DNS or captive-portal finding above and the internet returns."],
    },
    {
        "key": "fail_open", "severity": "medium", "min_count": 1,
        "pattern": r"fail[- ]?open",
        "title": "Fail-open happened: traffic went direct while the cloud was unreachable",
        "what": "The Forwarding Profile allows the client to send traffic directly to the internet when the Zscaler cloud cannot be reached, and that happened.",
        "means": "During those minutes the user browsed without any inspection: no URL filtering, no DLP. Convenient for the user, a blind spot for the customer.",
        "do": ["Decide with the customer: fail close (secure, users lose internet during a cloud outage) or fail open (available, unprotected). Managed devices with sensitive data usually run fail close.",
               "Fix the underlying reachability finding so fail-open stops being needed."],
    },
    {
        "key": "fail_close", "severity": "info", "min_count": 1,
        "pattern": r"fail[- ]?close",
        "title": "Fail-close happened: the device lost internet while the cloud was unreachable",
        "what": "The Forwarding Profile blocks all traffic when the Zscaler cloud cannot be reached, and that happened.",
        "means": "The user had no internet for those minutes. This is the secure choice; it only hurts when reachability is poor.",
        "do": ["Fix the reachability finding that triggered it (gateway unreachable, DNS, tunnel down).",
               "Check the profile's fail-close exception list for the customer's essential internal services."],
    },
    {
        "key": "mtu", "severity": "medium", "min_count": 2,
        "pattern": r"\bmtu\b.{0,40}\b(too (large|small)|fragment\w*|mismatch|reduc\w*|adjust\w*|error|issue)\b|fragment\w* (needed|error)|packet too (big|large)",
        "title": "Packet size (MTU) problems on the tunnel",
        "what": "Packets on the tunnel were being fragmented or rejected as too large.",
        "means": "Symptoms are pages that half-load, large uploads that stall and video calls that drop while small requests work. The path to the cloud has a smaller MTU than the tunnel assumes (VPNs and some ISPs).",
        "do": ["Lower the Z-Tunnel 2.0 MTU in the Forwarding Profile (Zscaler documents 1400 or below when a VPN is in the path).",
               "Check whether a VPN or PPPoE link is on the path; they cost 50 to 100 bytes."],
    },
    {
        "key": "timeouts", "severity": "medium", "min_count": 5,
        "pattern": r"\btimed? ?out\b|\btimeout\b",
        "exclude": r"captive|keepalive interval|timeout (value|set|=)",
        "title": "Many operations timed out",
        "what": "Requests from the client (to the cloud, the PAC host, the IdP or an update server) repeatedly waited and gave up.",
        "means": "The device's path to the internet was slow or half-broken during this period. On its own this is a symptom; the other findings here say what was timing out.",
        "do": ["Match the timestamps with the tunnel, DNS and gateway findings.",
               "If timeouts continue on a good network, ask for a fresh log bundle after a sign-out and sign-in."],
    },
]

def _bounded(pattern: str) -> str:
    """A signature with its open-ended word runs (\\w* and \\w+ after a
    prefix such as fail\\w*) bounded to 64 characters: a match restarted at
    every 'fail' inside one long run of letters would otherwise rescan the
    rest of the run each time (time growing with the square of its length).
    No real word in a log is longer."""
    return pattern.replace(r"\w*", r"\w{0,64}").replace(r"\w+", r"\w{1,64}")


_COMPILED = [(s, re.compile(_bounded(s["pattern"]), re.I), re.compile(_bounded(s["exclude"]), re.I) if s.get("exclude") else None)
             for s in SIGNATURES]
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def catalogue() -> List[Dict[str, str]]:
    """What the analyzer looks for, for the page's 'what is checked' list."""
    return [{"key": s["key"], "severity": s["severity"], "title": s["title"]} for s in SIGNATURES]


# ── Facts about the device ───────────────────────────────────────────
_FACT_VERSION = re.compile(r"\b(?:app|client|zcc|zscaler|zsa\w*)\b[^\n]{0,30}?\bversion\b[^0-9\n]{0,12}(\d+\.\d+\.\d+(?:\.\d+)?)", re.I)
_FACT_VERSION2 = re.compile(r"\bversion\b[^0-9\n]{0,10}(\d+\.\d+\.\d+(?:\.\d+)?)", re.I)
_FACT_OS = re.compile(r"\b(Windows (?:1[01]|Server[ \w]{0,12}|[\d.]+)|macOS[ \w.]{0,20}|Mac OS X[ \d.]{0,12}|Ubuntu[ \d.]{0,12}|Android[ \d.]{0,8}|iOS[ \d.]{0,8})", re.I)
_FACT_USER = re.compile(r"(?<![\w.+-])([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\b")
_FACT_CLOUD = re.compile(r"\b(zscaler(?:one|two|three|beta|gov|govus)?|zscloud)\.net\b", re.I)
_FACT_T2 = re.compile(r"z-?tunnel\s*2\.0|ztunnel2|dtls", re.I)
_FACT_T1 = re.compile(r"z-?tunnel\s*1\.0|ztunnel1", re.I)
_FACT_STATE = re.compile(r"(TUNNEL_STATE_[A-Z_]+)|tunnel state\s*(?:changed to|is|:|=)?\s*([A-Z][A-Z_]{3,40})\b")
_NORMALISE = re.compile(r"\d+")


def _normalise(msg: str) -> str:
    s = msg
    m = _TS_ISO.match(s) or _TS_US.match(s) or _TS_SYSLOG.match(s)
    if m:
        s = s[m.end():]
    s = re.sub(r"^\S*\)?\s*(\[[^\]]*\])?\s*", "", s)
    s = _NORMALISE.sub("#", s)
    return s.strip()[:160]


# ── Log analysis ─────────────────────────────────────────────────────
def analyze_logs(texts: List[Tuple[str, str]]) -> Dict[str, Any]:
    """texts: [(name, text)] for every log file. Findings, facts, top errors."""
    hits: Dict[str, Dict[str, Any]] = {}
    facts: Dict[str, Any] = {"versions": Counter(), "os": Counter(), "users": Counter(), "clouds": Counter(),
                             "tunnel": Counter(), "states": deque(maxlen=400)}   # the latest 400: the last state is the one that counts
    top_errors: Counter = Counter()
    error_example: Dict[str, str] = {}
    files_out: List[Dict[str, Any]] = []
    first_ts, last_ts = "", ""
    levels = Counter()
    for name, text in texts:
        n = 0
        f_first, f_last = "", ""
        for raw in text.splitlines():
            raw = raw[:MAX_LINE_CHARS]
            if not raw.strip():
                continue
            n += 1
            # A Client Connector line is short; a crafted one megabytes long
            # would cost every signature a full scan. Only its head is read.
            raw = raw[:MAX_LINE_CHARS]
            p = parse_line(raw)
            ts = p["ts"] if p["ts"] and not p["ts"].startswith("?") else ""
            if ts:
                f_first = f_first or ts
                f_last = ts
            if p["level"]:
                levels[p["level"]] += 1
            msg = p["msg"]
            low = msg.lower()
            if p["level"] == "error":
                key = _normalise(msg)
                top_errors[key] += 1
                error_example.setdefault(key, redact(msg))
            # facts
            if "version" in low and ("zsa" in low or "zcc" in low or "zscaler" in low or "app" in low or "client" in low):
                vm = _FACT_VERSION.search(msg) or _FACT_VERSION2.search(msg)
                if vm:
                    facts["versions"][vm.group(1)] += 1
            if "windows" in low or "macos" in low or "mac os" in low or "ubuntu" in low or "android" in low or "ios" in low:
                om = _FACT_OS.search(msg)
                if om:
                    facts["os"][om.group(1).strip()] += 1
            if "user" in low or "login" in low or "auth" in low:
                um = _FACT_USER.search(msg)
                if um:
                    facts["users"][um.group(1).lower()] += 1
            cm = _FACT_CLOUD.search(msg)
            if cm:
                facts["clouds"][cm.group(1).lower()] += 1
            if "tunnel" in low:
                if _FACT_T2.search(msg):
                    facts["tunnel"]["Z-Tunnel 2.0"] += 1
                elif _FACT_T1.search(msg):
                    facts["tunnel"]["Z-Tunnel 1.0"] += 1
                sm = _FACT_STATE.search(msg)
                if sm:
                    facts["states"].append((ts, (sm.group(1) or sm.group(2) or "").strip()))
            # signatures
            for sig, rx, ex in _COMPILED:
                if not rx.search(msg):
                    continue
                if ex and ex.search(msg):
                    continue
                h = hits.get(sig["key"])
                if h is None:
                    h = hits[sig["key"]] = {"count": 0, "first": "", "last": "", "files": Counter(), "evidence": [], "levels": Counter()}
                h["count"] += 1
                if ts:
                    h["first"] = h["first"] or ts
                    h["last"] = ts
                h["files"][name] += 1
                if p["level"]:
                    h["levels"][p["level"]] += 1
                if len(h["evidence"]) < MAX_EVIDENCE:
                    h["evidence"].append({"file": name, "ts": ts, "line": redact(msg)})
        files_out.append({"name": name, "kind": "log", "lines": n, "first": f_first, "last": f_last})
        if f_first:
            first_ts = min(first_ts, f_first) if first_ts else f_first
            last_ts = max(last_ts, f_last) if last_ts else f_last

    findings: List[Dict[str, Any]] = []
    for sig, _rx, _ex in _COMPILED:
        h = hits.get(sig["key"])
        if not h or h["count"] < sig.get("min_count", 1):
            continue
        findings.append({
            "key": sig["key"], "severity": sig["severity"], "title": sig["title"],
            "what": sig["what"], "means": sig["means"], "do": list(sig["do"]),
            "count": h["count"], "first": h["first"], "last": h["last"],
            "files": [{"name": k, "count": v} for k, v in h["files"].most_common(6)],
            "evidence": h["evidence"],
        })
    findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), -f["count"]))
    _add_context_notes(findings)

    last_state = ""
    for _ts, st in reversed(facts["states"]):
        if st:
            last_state = st
            break
    summary_facts = {
        "client_versions": [v for v, _ in facts["versions"].most_common(3)],
        "operating_systems": [v for v, _ in facts["os"].most_common(2)],
        "users": [u for u, _ in facts["users"].most_common(3)],
        "clouds": [c for c, _ in facts["clouds"].most_common(2)],
        "tunnel_versions": [t for t, _ in facts["tunnel"].most_common(2)],
        "last_tunnel_state": last_state,
    }
    top = [{"message": error_example.get(k, k), "count": c} for k, c in top_errors.most_common(TOP_ERRORS)]
    return {"files": files_out, "period": {"first": first_ts, "last": last_ts}, "facts": summary_facts,
            "levels": dict(levels), "findings": findings, "top_errors": top}


def _add_context_notes(findings: List[Dict[str, Any]]) -> None:
    """Cross-finding explanations: what is a cause and what is a symptom."""
    keys = {f["key"] for f in findings}
    by_key = {f["key"]: f for f in findings}
    if "captive_portal" in keys:
        for k in ("auth_failed", "tunnel_down", "dns_failed", "gateway_unreachable", "pac_download", "timeouts"):
            if k in keys:
                by_key[k]["context"] = "A captive portal was detected in the same logs. If these errors fall inside the minutes behind the portal, they are a symptom of it, not a separate fault."
    if "network_change" in keys:
        for k in ("tunnel_down", "timeouts", "dns_failed"):
            if k in keys and "context" not in by_key[k]:
                by_key[k]["context"] = "The device changed networks or woke from sleep repeatedly; short bursts right after those events are normal reconnections."
    if "trusted_network" in keys and "tunnel_down" in keys and "context" not in by_key["tunnel_down"]:
        by_key["tunnel_down"]["context"] = "The device was on a trusted network. If the Forwarding Profile turns the tunnel off on trusted networks, a tunnel that is 'down' there is by design."
    if "cert_error" in keys:
        for k in ("auth_failed", "pac_download", "config_failed", "update_failed"):
            if k in keys and "context" not in by_key[k]:
                by_key[k]["context"] = "Certificates were being rejected in the same logs; fix the TLS inspection or root-certificate problem first, this usually follows from it."
    if "proxy_auth" in keys:
        for k in ("auth_failed", "pac_download", "gateway_unreachable", "config_failed"):
            if k in keys and "context" not in by_key[k]:
                by_key[k]["context"] = "A proxy demanding authentication was in the path; remove it or configure it in the Forwarding Profile, then re-check this."
    if "disabled_by_user" in keys:
        by_key["disabled_by_user"]["context"] = "Users usually turn the client off because something else here was failing; fix that and make the password required."


# ── PAC analysis ─────────────────────────────────────────────────────
# The PAC file is read by pac_eval, the app's one PAC implementation: it is
# parsed and interpreted, never run. The findings below come from that
# parse (its returns and the conditions that lead to DIRECT) and from
# evaluating the PAC for a few common destinations.
_PAC_MACROS = ("${GATEWAY}", "${SECONDARY_GATEWAY}", "${GATEWAY_FX}", "${SECONDARY_GATEWAY_FX}", "${GATEWAY_HOST}", "${SECONDARY_GATEWAY_HOST}",
               "${SRCIP}", "${COUNTRY}", "${ZAPP_LOCAL_PROXY}", "${SUBCLOUD}", "${ZSCALER_LOCAL_PROXY}", "${CLOUD}")
_PRIVATE_NET = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)")
_RISKY_HOST = re.compile(r"(dropbox|box\.com|drive\.google|docs\.google|onedrive|sharepoint|1drv|slack|gmail|mail\.google|outlook|office365|office\.com|wetransfer|icloud|mega\.nz|github|gitlab|bitbucket|chatgpt|openai|anthropic|gemini|copilot|whatsapp|telegram|discord|teams\.microsoft|zoom)", re.I)
_BROAD = re.compile(r"^\*?\.?(\*|\*\.\w{2,3}|\w{2,3})$")
# Destinations every PAC is evaluated for: data channels, an ordinary
# site, an intranet name and a private address.
PAC_SAMPLES = ("https://drive.google.com/", "https://www.dropbox.com/", "https://mail.google.com/", "https://chatgpt.com/",
               "https://www.example.com/", "http://intranet/", "https://10.1.2.3/")

# A PAC pac_eval refuses (a regular expression, an array, a loop, switch...)
# is still read from its text, as before pac_eval: its string returns and
# the conditions in the lines just above each DIRECT. Text only, never run.
_PAC_RETURN = re.compile(r"return\s*(['\"])(.*?)\1", re.I | re.S)
_PAC_COND_FN = re.compile(r"\b(shExpMatch|dnsDomainIs|localHostOrDomainIs|isInNet|isPlainHostName)\s*\(([^()]*)\)", re.I)
_PAC_ISINNET = re.compile(r"isInNet\s*\(((?:[^()]|\([^()]*\))*)\)", re.I)
_PAC_STR = re.compile(r"['\"]([^'\"]+)['\"]")
_PAC_FN_NAMES = {"shexpmatch": "shExpMatch", "dnsdomainis": "dnsDomainIs", "localhostordomainis": "localHostOrDomainIs",
                 "isinnet": "isInNet", "isplainhostname": "isPlainHostName"}


def _pac_text_reading(body: str) -> Dict[str, Any]:
    """The text reading of a PAC pac_eval could not evaluate, in
    pac_eval.inspect's shape (returns, direct_rules, isinnet_on_host,
    calls): every literal answer in order, and every condition within four
    lines above a `return "DIRECT"`. Bounded as the evaluator is: the first
    pac_eval.MAX_SOURCE characters, each line up to MAX_LINE_CHARS."""
    import pac_eval
    lines = [ln[:MAX_LINE_CHARS] for ln in body[:pac_eval.MAX_SOURCE].splitlines()]
    returns = [m.group(2).strip() for m in _PAC_RETURN.finditer("\n".join(lines))]
    rules: List[Dict[str, Any]] = []
    seen = set()
    for i, line in enumerate(lines):
        if not re.search(r"return\s*['\"]\s*DIRECT\s*['\"]", line, re.I):
            continue
        window = "\n".join(lines[max(0, i - 4): i + 1])
        found = [("isInNet", s[0]) for s in (_PAC_STR.findall(a) for a in _PAC_ISINNET.findall(window)) if s]
        for fn, args in _PAC_COND_FN.findall(window):
            fn = _PAC_FN_NAMES[fn.lower()]
            if fn == "isPlainHostName":
                found.append((fn, ""))
            elif fn != "isInNet":
                found += [(fn, s) for s in _PAC_STR.findall(args)]
        for fn, value in found:
            if (fn, value) not in seen:
                seen.add((fn, value))
                rules.append({"fn": fn, "value": value, "line": i + 1})
    text = "\n".join(lines)
    calls = {c for c in ("myIpAddress", "isResolvable") if re.search(rf"\b{c}\s*\(", text)}
    return {"returns": returns, "direct_rules": rules, "isinnet_on_host": bool(re.search(r"isInNet\s*\(\s*host\s*,", text, re.I)),
            "calls": calls}


def analyze_pac(name: str, text: str) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    body = text
    if not _PAC_MARK.search(body):
        findings.append({"severity": "critical", "title": "This is not a working PAC file",
                         "what": "The file has no FindProxyForURL(url, host) function, which every PAC file must define.",
                         "means": "A browser or Client Connector given this file will fail to load it and fall back to direct connections (no Zscaler).",
                         "do": ["Check that the right file was exported (the PAC URL in the ZCC app profile downloads as plain text).",
                                "If this is a template, add function FindProxyForURL(url, host) { ... } around the rules."], "evidence": []})
        return {"name": name, "kind": "pac", "summary": {}, "findings": findings}

    opens, closes = body.count("{"), body.count("}")
    if opens != closes:
        findings.append({"severity": "critical", "title": "Unbalanced braces: the PAC will not parse",
                         "what": f"The file opens {opens} braces and closes {closes}.",
                         "means": "A PAC with a syntax error is rejected by the browser and by Client Connector; the device then goes direct.",
                         "do": ["Open the file in an editor with bracket matching and fix the block that is not closed.",
                                "Test in a browser: about:policies or the OS proxy settings show a PAC parse error."], "evidence": []})
    import pac_eval
    info = pac_eval.inspect(body)
    text_only = not info["ok"]
    if text_only:
        findings.append({"severity": "medium", "title": "The PAC could not be evaluated safely",
                         "what": f"The app {info['error']}.",
                         "means": "PAC files are read here without running them, and only the subset PAC files normally use is understood. This file uses something outside it, so its answers were not checked for any destination; its answers and bypasses below were read from the text only.",
                         "do": ["Test the PAC in a browser (or Client Connector) and read its bypasses by hand.",
                                "Prefer plain if / else with shExpMatch, dnsDomainIs and isInNet: they are easier to review and faster for the browser."], "evidence": []})
        info = dict(_pac_text_reading(body), ok=False, error=info["error"])
    returns = [r for r in info["returns"]]
    literal = [r.strip() for r in returns if r is not None]
    if not returns and (info["ok"] or not re.search(r"\breturn\b", body)):
        findings.append({"severity": "critical", "title": "No return statement: the PAC decides nothing",
                         "what": "FindProxyForURL never returns a proxy string.",
                         "means": "Every request gets an undefined answer and the browser goes direct.",
                         "do": ["End the function with a final return, for example return \"PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT\";"], "evidence": []})
    macros = [m for m in _PAC_MACROS if m in body]
    entries = [e for r in literal for e in pac_eval.proxy_entries(r)]
    hardcoded = sorted({e["host"] for e in entries if e["kind"] == "zscaler" and e["host"] and not e["host"].startswith("${") and e["host"] != "127.0.0.1"})
    gateway_hosts = sorted({e["host"] for e in entries if e["host"]})
    last_return = (returns[-1] or "").strip() if returns else ""
    if returns and returns[-1] is None:
        # The last answer is computed: what the PAC answers for an ordinary site.
        ev = pac_eval.evaluate(body, "https://www.example.com/", "www.example.com", dns="assume_public")
        last_return = ev["result"] or ""
    default_action = "direct" if last_return.upper().strip() == "DIRECT" else ("proxy" if last_return else "none")

    if hardcoded and not any(m in body for m in ("${GATEWAY}", "${GATEWAY_FX}", "${GATEWAY_HOST}")):
        findings.append({"severity": "medium", "title": "Zscaler gateway is hard-coded instead of using ${GATEWAY}",
                         "what": f"The PAC sends traffic to a fixed gateway name: {', '.join(hardcoded)}.",
                         "means": "Every user is pinned to one data centre. A travelling user is routed to the wrong region (slow) and there is no automatic failover if that data centre has an incident.",
                         "do": ["Replace the fixed name with the Zscaler macros: PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80. Zscaler fills them with the nearest healthy data centres when the PAC is served.",
                                "Host the PAC on Zscaler (ZIA Admin Portal > Administration > Hosted PAC Files) so the macros work."], "evidence": hardcoded[:4]})
    if last_return and default_action == "direct":
        findings.append({"severity": "high", "title": "The default answer is DIRECT: anything not matched bypasses Zscaler",
                         "what": "The last return in FindProxyForURL is DIRECT, so every request that no earlier rule matched goes straight to the internet.",
                         "means": "For a PAC that is meant to forward traffic to Zscaler this is backwards: only the listed hosts would be inspected, everything else (new SaaS apps, personal webmail, AI tools) skips DLP. It is only right for a bypass PAC used together with Client Connector's tunnel, where the tunnel catches the rest.",
                         "do": ["If this PAC forwards traffic (Forwarding Profile PAC or browser PAC): make the last line return \"PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT\".",
                                "If it is the app profile's bypass PAC with Z-Tunnel in use, DIRECT as the default is expected; check the Forwarding Profile to be sure."], "evidence": [redact(last_return)]})
    if last_return and default_action == "proxy":
        if last_return.upper().rstrip(" ;").endswith("DIRECT"):
            findings.append({"severity": "info", "title": "Fail-open: if every listed gateway is unreachable, traffic goes direct",
                             "what": "The final proxy string ends with DIRECT.",
                             "means": "Users keep internet access during a Zscaler or network outage, unprotected for that time. Removing the trailing DIRECT makes it fail-closed (secure, but no internet during an outage).",
                             "do": ["Decide with the customer which they want; managed devices with sensitive data usually run fail-closed with Client Connector's fail-close setting."], "evidence": [redact(last_return)]})
        else:
            findings.append({"severity": "info", "title": "Fail-closed: if every listed gateway is unreachable, the browser has no route",
                             "what": "The final proxy string has no DIRECT fallback.",
                             "means": "Secure by default: nothing bypasses Zscaler, but a cloud or network outage means no internet until it recovers.",
                             "do": ["Keep it if the customer accepts the trade-off; add a secondary gateway (${SECONDARY_GATEWAY}) so a single data-centre incident does not take users offline."], "evidence": [redact(last_return)]})
        if "${SECONDARY_GATEWAY}" not in body and "${SECONDARY_GATEWAY_FX}" not in body and "${SECONDARY_GATEWAY_HOST}" not in body and len(gateway_hosts) < 2:
            findings.append({"severity": "medium", "title": "Only one gateway: no failover if that data centre is down",
                             "what": "The proxy string names a single gateway.",
                             "means": "If that data centre has an incident, users lose internet (fail-closed) or go unprotected (fail-open) until the PAC is changed.",
                             "do": ["Add the secondary: PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80"], "evidence": []})

    # Bypass inventory: the conditions that lead to a DIRECT answer.
    bypasses: List[Dict[str, Any]] = []
    for r in info["direct_rules"]:
        fn, value, line = r["fn"], r["value"], r["line"]
        if fn == "isPlainHostName":
            bypasses.append({"kind": "plain host names", "value": "single-label names (intranet)", "line": line, "risk": "ok"})
        elif fn == "isInNet":
            risk = "public-range" if (re.match(r"^\d+\.\d+\.\d+\.\d+$", value) and not _PRIVATE_NET.match(value)) else "ok"
            bypasses.append({"kind": "isInNet", "value": value[:200], "line": line, "risk": risk})
        else:
            risk = "data-channel" if _RISKY_HOST.search(value[:300]) else "broad" if _BROAD.match(value[:20]) else "ok"
            bypasses.append({"kind": fn, "value": value[:200], "line": line, "risk": risk})
    risky = [b for b in bypasses if b["risk"] in ("data-channel", "broad", "public-range")]
    if risky:
        findings.append({"severity": "high", "title": f"{len(risky)} bypass{'es' if len(risky) != 1 else ''} send data channels or wide ranges around Zscaler",
                         "what": "These DIRECT rules match file-sharing, webmail, chat or AI services, a whole top-level domain, or a public IP range.",
                         "means": "Traffic that goes DIRECT is never decrypted, URL-filtered or checked by DLP. A bypass for a file-sharing or webmail service is a data-loss channel the customer has opened on purpose or by accident.",
                         "do": ["Ask why each one exists; most were added years ago for a problem that a Zscaler SSL exemption or a cloud-app policy now solves without a full bypass.",
                                "Prefer narrower fixes: an SSL inspection exemption for a pinned app, a Cloud App Control rule, or a ZCC app-profile bypass limited to the exact host."],
                         "evidence": [f"line {b['line']}: {b['kind']}({b['value']}) [{b['risk']}]" for b in risky[:8]]})
    if not any(b["kind"] == "plain host names" for b in bypasses) and not any(b["kind"] == "isInNet" and _PRIVATE_NET.match(b["value"]) for b in bypasses):
        findings.append({"severity": "low", "title": "No bypass for private addresses or plain host names",
                         "what": "The PAC does not send RFC 1918 ranges or single-label intranet names DIRECT.",
                         "means": "Intranet sites and printers would be sent to Zscaler, which cannot reach them, so they break. Zscaler's reference PAC starts with these bypasses.",
                         "do": ["Add near the top: if (isPlainHostName(host) || shExpMatch(host, \"*.local\") || isInNet(dnsResolve(host), \"10.0.0.0\", \"255.0.0.0\") || isInNet(dnsResolve(host), \"172.16.0.0\", \"255.240.0.0\") || isInNet(dnsResolve(host), \"192.168.0.0\", \"255.255.0.0\")) return \"DIRECT\";"], "evidence": []})
    if info["isinnet_on_host"]:
        findings.append({"severity": "medium", "title": "isInNet(host, …) forces a DNS lookup on every request",
                         "what": "isInNet is called with the host name instead of an address.",
                         "means": "The browser resolves every host name before it can decide, which makes page loads slow and can leak intranet names to public DNS. Browsers differ in how they handle it.",
                         "do": ["Only call isInNet when the host is already an IP (test with a regex) or wrap it: isInNet(dnsResolve(host), ...) inside a check that the name is worth resolving.",
                                "Zscaler's reference PAC uses this pattern."], "evidence": []})
    if "myIpAddress" in info["calls"]:
        findings.append({"severity": "low", "title": "myIpAddress() is used",
                         "what": "The PAC decides based on the device's own IP address.",
                         "means": "With a VPN, Wi-Fi plus Ethernet, or virtual adapters the browser may return any of the adapters' addresses, so the rule behaves differently from device to device. Client Connector's trusted-network detection is the reliable way to detect 'in the office'.",
                         "do": ["Move location logic to the Forwarding Profile's trusted-network criteria and keep the PAC simple."], "evidence": []})
    if "isResolvable" in info["calls"]:
        findings.append({"severity": "low", "title": "isResolvable() adds a DNS lookup per request",
                         "what": "The PAC calls isResolvable.",
                         "means": "Each call waits for DNS; on a slow resolver every page waits with it.",
                         "do": ["Replace it with host-name pattern rules where possible."], "evidence": []})
    ports = sorted({e["port"] for e in entries if e["port"]})
    if any(p in ("9400", "9480", "9443") for p in ports):
        findings.append({"severity": "info", "title": "Z-Tunnel 1.0 / Client Connector local ports are referenced",
                         "what": f"Proxy ports in use: {', '.join(ports)}.",
                         "means": "Ports 9400 and 9480 are Client Connector's local listener (used by ZCC's own PAC); a browser PAC that points at them only works with Client Connector running.",
                         "do": ["Fine for the app profile's PAC; for a standalone browser PAC use the cloud gateways on 80 or 443."], "evidence": []})

    # What the PAC answers for common destinations, evaluated (never run).
    samples: List[Dict[str, Any]] = []
    if info["ok"]:
        for u in PAC_SAMPLES:
            ev = pac_eval.evaluate(body, u, dns="assume_public")
            if ev["status"] == "error":
                samples = [{"url": u, "result": None, "kind": "error", "depends_on": [], "error": ev["error"]}]
                break
            samples.append({"url": u, "result": ev["result"] or " | ".join(o["result"] for o in ev["outcomes"]), "kind": ev["kind"],
                            "depends_on": ev["depends_on"], "error": None})
        leaks = [s for s in samples[:4] if s["kind"] in ("direct", "other_proxy")]
        if leaks and not risky:
            findings.append({"severity": "high", "title": "Data channels are answered without Zscaler",
                             "what": "Evaluated, the PAC sends these services DIRECT or to another proxy: " + ", ".join(s["url"] for s in leaks) + ".",
                             "means": "Uploads to them are never decrypted, URL-filtered or checked by DLP.",
                             "do": ["Find the branch that answers this (the evaluation table below) and send these services to Zscaler."], "evidence": [f"{s['url']} → {s['result']}" for s in leaks[:4]]})

    lines = body.count("\n") + 1
    summary = {"macros": macros, "gateways": gateway_hosts[:6], "hardcoded_gateways": hardcoded[:6], "default": default_action,
               "returns": len(returns), "bypasses": bypasses[:200], "bypass_count": len(bypasses), "lines": lines,
               "evaluation": {"ok": info["ok"], "error": info["error"], "samples": samples}}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"name": name, "kind": "pac", "summary": summary, "findings": findings}


# ── Entry point ──────────────────────────────────────────────────────
def analyze(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not files:
        raise ValueError("no files were uploaded")
    members, notes = expand(files)
    logs: List[Tuple[str, str]] = []
    pacs: List[Dict[str, Any]] = []
    for name, data in members:
        text = _to_text(data)
        if kind_of(name, text) == "pac":
            pacs.append(analyze_pac(name, text))
        else:
            logs.append((name, text))
    if not logs and not pacs:
        raise ValueError("nothing readable was found: upload the ZIP that Client Connector's Export Logs produced, individual .log files, or a PAC file")
    result: Dict[str, Any] = {"ok": True, "notes": notes, "checked": catalogue(), "pac": pacs}
    if logs:
        result["logs"] = analyze_logs(logs)
    else:
        result["logs"] = None
    result["verdict"] = _verdict(result)
    return result


def _verdict(result: Dict[str, Any]) -> Dict[str, str]:
    """One sentence a junior engineer can read first."""
    logs = result.get("logs") or {}
    findings = logs.get("findings") or []
    sev = Counter(f["severity"] for f in findings)
    pac_sev = Counter(f["severity"] for p in result.get("pac") or [] for f in p.get("findings") or [])
    if sev.get("critical"):
        worst = next(f for f in findings if f["severity"] == "critical")
        return {"level": "critical", "headline": "The user was not protected for part of this period.", "detail": f"Start with: {worst['title']}."}
    if sev.get("high"):
        worst = next(f for f in findings if f["severity"] == "high")
        return {"level": "high", "headline": "Protection was degraded or the client was struggling to reach the cloud.", "detail": f"Start with: {worst['title']}."}
    if pac_sev.get("critical") or pac_sev.get("high"):
        return {"level": "high", "headline": "The PAC file has a problem that changes what is protected.", "detail": "Read the PAC findings below, top one first."}
    if sev.get("medium") or pac_sev.get("medium"):
        return {"level": "medium", "headline": "The client was working, with things worth tuning.", "detail": "Nothing here stops the user; each medium finding says what to improve."}
    if findings or (logs.get("top_errors")):
        return {"level": "info", "headline": "The client looks healthy. Only context and unrecognised errors are listed.", "detail": "Read the top repeated errors; if the user reports a problem, ask for a fresh bundle taken while it happens."}
    if pac_sev.get("low"):
        return {"level": "info", "headline": "The PAC file works; a few things in it are worth tidying.", "detail": "Read the low findings below; none changes what is protected today."}
    if result.get("pac") and not logs:
        return {"level": "ok", "headline": "The PAC file passes every check here.", "detail": "Its bypass list is shown below so you can confirm each one is intended."}
    return {"level": "ok", "headline": "Nothing wrong was found in these logs.", "detail": "If the user still has a problem, the logs may not cover the time it happened: ask for Export Logs taken right after the problem."}
