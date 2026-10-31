"""Windows DNS output of the client-hostname forward-zone generator
(dns_forward_zones.render_windows_powershell / render_windows_dnscmd):
one Add-DnsServerConditionalForwarderZone (PowerShell) or
`dnscmd /ZoneAdd ... /Forwarder` (cmd.exe) line per client name, from the
same checked labels and resolver addresses as the Unbound and BIND files.

The grammar checkers below accept only the exact line shapes the module
writes, so anything a tenant can type into a hostname that reached a
command line (a quote, ';', '`', '$', '|', '&', a space or a newline) would
fail them. No DNS server, tenant or network is touched."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re

import pytest

import dns_forward_zones as dfz

NOW = dt.datetime(2026, 10, 31, 12, 0, tzinfo=dt.timezone.utc)
NAME = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
PS_LINE = re.compile(rf"\Aif \(Get-DnsServerZone -Name '({NAME})' -ErrorAction SilentlyContinue\) \{{ Write-Output 'exists, skipped: \1' \}} "
                     rf"else \{{ Add-DnsServerConditionalForwarderZone -Name '\1' -MasterServers \$servers \}}\Z")
PS_SERVERS = re.compile(r"\A\$servers = @\(('[0-9a-f.:]+'(?:, '[0-9a-f.:]+')*)\)\Z")
CMD_LINE = re.compile(rf"\Adnscmd /ZoneAdd ({NAME}) /Forwarder ([0-9a-f.: ]+)\Z")
INJECT = ['pc"; forward-addr: 6.6.6.6 #', "pc\nRemove-DnsServerZone x", "pc'; Remove-DnsServerZone -Name corp; '", "pc`whoami`", "pc$(calc)",
          "pc & del /q c:\\*", "pc | net user", "pc\r\nformat c:", "pc x", "pc\u202e1", "pc\x00x", "=cmd|' /c calc'!A0"]


def dev(host, platform="Windows", reg="registered", user="", seen=3600):
    return {"hostname": host, "platform": platform, "registration": reg, "user": user, "seconds_since_seen": seen}


def build(devs, **kw):
    kw.setdefault("domain", "corp.example.com")
    kw.setdefault("resolvers", "10.0.0.12")
    return dfz.build(devs, now=NOW, **kw)


def check_powershell(text):
    """The PowerShell grammar the module writes: comments, two fixed lines,
    one $servers array of addresses and one guarded add per name."""
    names, servers = [], None
    for ln in text.split("\r\n"):
        if not ln or ln.startswith("# "):
            continue
        if ln == "$ErrorActionPreference = 'Stop'":
            continue
        m = PS_SERVERS.match(ln)
        if m:
            assert servers is None, "one $servers line"
            servers = [s.strip("'") for s in m.group(1).split(", ")]
            for s in servers:
                ipaddress.ip_address(s)
            continue
        m = PS_LINE.match(ln)
        assert m, f"unexpected PowerShell line: {ln!r}"
        names.append(m.group(1))
    return names, servers


def check_dnscmd(text):
    names = []
    for ln in text.split("\r\n"):
        if not ln or ln.startswith("REM "):
            continue
        m = CMD_LINE.match(ln)
        assert m, f"unexpected dnscmd line: {ln!r}"
        for a in m.group(2).split(" "):
            ipaddress.ip_address(a)
        names.append((m.group(1), m.group(2).split(" ")))
    return names


def test_powershell_adds_one_conditional_forwarder_per_name():
    """ASVS V5.3.6 · CWE-78 · WSTG-INPV-12: the PowerShell file has one guarded Add-DnsServerConditionalForwarderZone per client name, to the checked resolver addresses, and skips a zone that exists."""
    # Arrange
    devs = [dev("LKF-LT-0001"), dev("Rowan's MacBook Pro", "macOS"), dev("pc.1", "Linux")]
    # Act
    out = build(devs, resolvers="10.0.0.12, 2001:db8::53")
    names, servers = check_powershell(out["files"]["windows_ps"])
    # Assert
    assert sorted(names) == ["lkf-lt-0001.corp.example.com", "pc.corp.example.com", "rowans-macbook-pro.corp.example.com"]
    assert servers == ["10.0.0.12", "2001:db8::53"]
    assert out["files"]["windows_ps"].endswith("\r\n") and "\n" not in out["files"]["windows_ps"].replace("\r\n", "")


def test_dnscmd_adds_one_forwarder_zone_per_name():
    """ASVS V5.3.6 · CWE-78 · WSTG-INPV-12: the dnscmd file has one `dnscmd /ZoneAdd <name> /Forwarder <addresses>` per client name and nothing else outside REM comments."""
    # Arrange
    devs = [dev("LKF-LT-0001"), dev("LKF-LT-0002")]
    # Act
    out = build(devs, resolvers="10.0.0.12 10.0.0.13")
    # Assert
    assert check_dnscmd(out["files"]["windows_dnscmd"]) == [("lkf-lt-0001.corp.example.com", ["10.0.0.12", "10.0.0.13"]),
                                                           ("lkf-lt-0002.corp.example.com", ["10.0.0.12", "10.0.0.13"])]


def test_mapped_domains_get_their_own_windows_lines():
    """ASVS V5.1.3 · CWE-20: an e-mail domain mapped to a second DNS domain gives the device a second name in both Windows files."""
    # Arrange
    devs = [dev("LKF-LT-0001", user="avery@subsidiary.example")]
    # Act
    out = build(devs, mappings="subsidiary.example: sub.corp.example")
    # Assert
    ps, _ = check_powershell(out["files"]["windows_ps"])
    cmd = [n for n, _ in check_dnscmd(out["files"]["windows_dnscmd"])]
    assert "lkf-lt-0001.sub.corp.example" in ps and ps == cmd


def test_nothing_a_tenant_types_reaches_a_windows_command_line():
    """ASVS V5.3.8 · CWE-78 · CWE-77 · CWE-93 · WSTG-INPV-12: quotes, ';', backticks, '$(...)', '&', '|', CR/LF, spaces, bidi and NUL in hostnames never reach the PowerShell or dnscmd text; every line passes the strict grammar."""
    # Arrange
    devs = [dev(h) for h in INJECT]
    # Act
    out = build(devs, resolvers="10.0.0.12")
    # Assert
    ps, _ = check_powershell(out["files"]["windows_ps"])
    cmd = check_dnscmd(out["files"]["windows_dnscmd"])
    assert ps and len(ps) == len(cmd)
    for key in ("windows_ps", "windows_dnscmd"):
        text = out["files"][key]
        for bad in ("6.6.6.6", "Remove-DnsServerZone -Name corp", "`", "$(", "&", "|", "del /q", "net user", "format c:", '"', "\x00", "\u202e"):
            assert bad not in text, (key, bad)


def test_the_windows_renderers_refuse_an_unchecked_name_or_address():
    """ASVS V5.3.6 · CWE-20 · CWE-1287: called directly with a name or an address that did not come through the checks, the Windows renderers refuse (defence in depth) instead of writing it."""
    # Arrange
    meta = {"generated_at": "2026-10-31T12:00:00Z", "domain": "corp.example.com", "resolvers": ["10.0.0.12"]}
    # Act / Assert
    for fn in (dfz.render_windows_powershell, dfz.render_windows_dnscmd):
        with pytest.raises(dfz.DnsInputError):
            fn([("corp.example.com", "pc';calc;'")], ["10.0.0.12"], meta)
        with pytest.raises(ValueError):
            fn([("corp.example.com", "pc1")], ["10.0.0.12; calc"], meta)


def test_the_windows_comment_lines_carry_no_tenant_text():
    """CWE-117 · ASVS V5.3.6: the PowerShell and REM comment lines hold only the date, the checked domain and the addresses, never a hostname."""
    # Arrange
    devs = [dev("pc\n#evil & calc")]
    # Act
    out = build(devs)
    # Assert
    for key, mark in (("windows_ps", "# "), ("windows_dnscmd", "REM ")):
        comments = [ln for ln in out["files"][key].split("\r\n") if ln.startswith(mark)]
        assert comments and not any("evil" in c or "calc" in c for c in comments)


def test_the_windows_files_have_download_names():
    """ASVS V12.5.1 · CWE-434: the two Windows files have fixed download names (.ps1 and .cmd) and a text media type."""
    # Act / Assert
    assert dfz.FILES["windows_ps"] == ("zcc_client_zones_windows.ps1", "text/plain; charset=utf-8")
    assert dfz.FILES["windows_dnscmd"] == ("zcc_client_zones_dnscmd.cmd", "text/plain; charset=utf-8")
