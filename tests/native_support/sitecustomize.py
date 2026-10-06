"""Subprocess-only native smoke safety guard; never shipped on production PATH."""
import ipaddress
import json
import os
from pathlib import Path
import socket

if os.environ.get('NATIVE_GUARD_MARKER'):
    Path(os.environ['NATIVE_GUARD_MARKER']).write_text('loopback-only\n')
    _dns, _connect, _connect_ex = socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex

    def _check(host):
        if host is None:
            return
        if isinstance(host, bytes):
            host = host.decode('ascii', 'replace')
        allowed = str(host).lower() == 'localhost'
        try:
            allowed = allowed or ipaddress.ip_address(str(host).split('%', 1)[0]).is_loopback
        except ValueError:
            pass
        if not allowed:
            with open(os.environ['NATIVE_EGRESS_LOG'], 'a', encoding='utf-8') as log:
                log.write(json.dumps({'blocked_host': str(host)}) + '\n')
            raise OSError('Native install smoke permits loopback only')

    def _safe_dns(host, *args, **kwargs):
        _check(host)
        return _dns(host, *args, **kwargs)

    def _safe_connect(sock, address):
        if isinstance(address, tuple):
            _check(address[0])
        return _connect(sock, address)

    def _safe_connect_ex(sock, address):
        if isinstance(address, tuple):
            _check(address[0])
        return _connect_ex(sock, address)

    socket.getaddrinfo = _safe_dns
    socket.socket.connect = _safe_connect
    socket.socket.connect_ex = _safe_connect_ex
