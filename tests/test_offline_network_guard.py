"""Prove that accidental real authentication cannot leave the test process."""
import socket
import pytest


@pytest.mark.parametrize("host", ["acme.zscaler.com", "login.zscaler.com", "example.com", "198.51.100.1", "2001:db8::1"])
def test_nonlocal_dns_is_blocked_before_resolution(host):
    with pytest.raises(RuntimeError, match="Offline test guard"):
        socket.getaddrinfo(host, 443)


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
def test_nonlocal_ip_connection_is_blocked(method):
    with socket.socket() as sock:
        with pytest.raises(RuntimeError, match="Offline test guard"):
            getattr(sock, method)(("198.51.100.1", 443))


def test_loopback_fixture_server_is_allowed():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=1):
            conn, _ = server.accept()
            conn.close()
