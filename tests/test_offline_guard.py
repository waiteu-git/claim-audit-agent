"""テスト基盤: 外向き通信が遮断され、ループバックだけ通ること（T3 のローカル TLS 試験の前提）。"""
import socket

import pytest

from tests.conftest import NetworkBlockedError, _host_is_local


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.1.2.3", "", None, b"localhost"])
def test_loopback_hosts_are_recognised(host):
    assert _host_is_local(host)


@pytest.mark.parametrize("host", ["8.8.8.8", "169.254.169.254", "10.0.0.1", "example.invalid", "metadata.google.internal", 123])
def test_other_hosts_are_not_local(host):
    assert not _host_is_local(host)


@pytest.mark.expect_network_block
def test_outbound_connections_and_dns_are_blocked():
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("192.0.2.1", 80), timeout=0.2)
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.invalid", 443)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(NetworkBlockedError):
            s.connect(("203.0.113.5", 443))
        with pytest.raises(NetworkBlockedError):
            s.connect_ex(("203.0.113.5", 443))


def test_loopback_connections_still_work():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
            conn, _ = srv.accept()
            c.sendall(b"ping")
            assert conn.recv(4) == b"ping"
            conn.close()
    finally:
        srv.close()


async def test_asyncio_loopback_works_under_the_guard():
    import asyncio

    async def handle(reader, writer):
        writer.write(await reader.read(4))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"echo")
    await w.drain()
    assert await r.read(4) == b"echo"
    w.close()
    server.close()
    await server.wait_closed()
