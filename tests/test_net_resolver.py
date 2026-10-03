"""GuardedResolver と PinnedBackend（app/net/resolver.py・backend.py）。名前解決・接続はフェイクで、完全オフライン。"""
import asyncio
import socket

import httpcore
import pytest

from app.net.backend import PinnedBackend, PinViolation
from app.net.resolver import GuardedResolver, IpBlocked, ResolveFailed, system_resolver
from tests.net_support import FakeInternet


def _resolver(answers, **kw) -> GuardedResolver:
    async def fake(host: str):
        if isinstance(answers, Exception):
            raise answers
        return answers

    return GuardedResolver(fake, **kw)


async def test_returns_checked_addresses_ipv4_first_and_deduplicated():
    r = _resolver(["2606:4700:4700::1111", "8.8.8.8", "8.8.8.8", "8.8.4.4"])
    assert await r.resolve("a.example.invalid") == ("8.8.8.8", "8.8.4.4", "2606:4700:4700::1111")


async def test_one_private_address_rejects_the_whole_answer():
    for answer in (["8.8.8.8", "10.0.0.5"], ["10.0.0.5", "8.8.8.8"], ["8.8.8.8", "::ffff:169.254.169.254"]):
        with pytest.raises(IpBlocked):
            await _resolver(answer).resolve("a.example.invalid")


async def test_addresses_beyond_the_connection_limit_are_still_checked():
    """接続を試すのは先頭4件までだが、検査は全件。5件目の私有 IP でも全体拒否。"""
    answer = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "10.0.0.5"]
    with pytest.raises(IpBlocked):
        await _resolver(answer).resolve("a.example.invalid")
    ok = await _resolver(answer[:4] + ["9.9.9.9"]).resolve("a.example.invalid")
    assert ok == ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")  # 検査済みだが試すのは先頭4件


async def test_blocked_exception_carries_the_verdict_but_never_the_ip():
    with pytest.raises(IpBlocked) as ei:
        await _resolver(["169.254.169.254"]).resolve("a.example.invalid")
    assert ei.value.verdict.code == "ip.metadata"
    assert "169.254" not in str(ei.value)


@pytest.mark.parametrize("answer", [[], None, ()])
async def test_no_answer_is_a_resolve_failure(answer):
    with pytest.raises(ResolveFailed) as ei:
        await _resolver(answer).resolve("a.example.invalid")
    assert ei.value.code == "dns.no_answer"


async def test_resolver_exception_and_timeout_are_resolve_failures_not_crashes():
    with pytest.raises(ResolveFailed) as ei:
        await _resolver(socket.gaierror(-2, "boom")).resolve("a.example.invalid")
    assert ei.value.code == "dns.error"

    async def slow(host: str):
        await asyncio.sleep(5)
        return ["8.8.8.8"]

    with pytest.raises(ResolveFailed) as ei2:
        await GuardedResolver(slow, timeout_s=0.05).resolve("a.example.invalid")
    assert ei2.value.code == "dns.timeout"


async def test_non_string_answers_fail_closed():
    with pytest.raises(IpBlocked):
        await _resolver([None]).resolve("a.example.invalid")  # type: ignore[list-item]


async def test_outer_cancellation_is_not_swallowed():
    async def hang(host: str):
        await asyncio.sleep(30)

    task = asyncio.create_task(GuardedResolver(hang, timeout_s=10).resolve("a.example.invalid"))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_system_resolver_collects_ipv4_and_ipv6_and_keeps_zone_ids(monkeypatch: pytest.MonkeyPatch):
    """既定の名前解決は loop.getaddrinfo の全応答を集める。ゾーン ID 付きもそのまま返し、検査側が拒否する。"""
    fake = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%en0", 443, 0, 4)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: fake)
    assert await system_resolver("a.example.invalid") == ["8.8.8.8", "2606:4700:4700::1111", "fe80::1%en0"]
    with pytest.raises(IpBlocked) as ei:
        await GuardedResolver(system_resolver).resolve("a.example.invalid")
    assert ei.value.verdict.code == "ip.scope_id"


@pytest.mark.expect_network_block
async def test_default_wiring_reaches_for_real_dns_and_the_offline_guard_stops_it():
    """既定のまま（解決関数を注入しない）だと実 DNS に出ようとする＝注入し忘れがテストで必ず落ちる、という確認。"""
    with pytest.raises(ResolveFailed):
        await GuardedResolver().resolve("blocked-by-offline-guard.example.invalid")


# ---------------------------------------------------------------- PinnedBackend
async def test_backend_connects_only_to_pinned_ips_by_ip_literal():
    net = FakeInternet()
    be = PinnedBackend({"a.example.invalid": ("8.8.8.8",)}, net)
    await be.connect_tcp("a.example.invalid", 443, timeout=1.0)
    assert net.connects == [("8.8.8.8", 443)] and net.non_ip_connects == []


@pytest.mark.parametrize(("host", "port"), [("unpinned.example.invalid", 443), ("a.example.invalid", 80), ("a.example.invalid", 8443)])
async def test_backend_refuses_unpinned_hosts_and_other_ports_without_connecting(host: str, port: int):
    net = FakeInternet()
    be = PinnedBackend({"a.example.invalid": ("8.8.8.8",)}, net)
    with pytest.raises(PinViolation):
        await be.connect_tcp(host, port, timeout=1.0)
    assert net.connects == []


async def test_backend_refuses_unix_sockets_and_empty_pins():
    net = FakeInternet()
    be = PinnedBackend({"a.example.invalid": ()}, net)
    with pytest.raises(PinViolation):
        await be.connect_unix_socket("/var/run/docker.sock")
    with pytest.raises(PinViolation):
        await be.connect_tcp("a.example.invalid", 443)
    assert net.connects == []


async def test_backend_falls_back_to_the_next_checked_ip_only_on_connect_errors():
    net = FakeInternet(connect_errors={"8.8.8.8": httpcore.ConnectError("x")})
    be = PinnedBackend({"a.example.invalid": ("8.8.8.8", "8.8.4.4")}, net)
    await be.connect_tcp("a.example.invalid", 443, timeout=1.0)
    assert net.connected_ips == ("8.8.8.8", "8.8.4.4")

    net2 = FakeInternet(connect_errors={"8.8.8.8": httpcore.ConnectError("x"), "8.8.4.4": httpcore.ConnectTimeout("y")})
    be2 = PinnedBackend({"a.example.invalid": ("8.8.8.8", "8.8.4.4")}, net2)
    with pytest.raises(httpcore.ConnectTimeout):
        await be2.connect_tcp("a.example.invalid", 443, timeout=1.0)
    assert net2.connected_ips == ("8.8.8.8", "8.8.4.4")  # 検査済みの2つ以外へは行かない


async def test_backend_attempt_limit_and_misconfiguration_never_connect_unchecked():
    net = FakeInternet(connect_errors={ip: httpcore.ConnectError("x") for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1")})
    be = PinnedBackend({"a.example.invalid": ("8.8.8.8", "8.8.4.4", "1.1.1.1")}, net, max_attempts=2)
    with pytest.raises(httpcore.ConnectError):
        await be.connect_tcp("a.example.invalid", 443)
    assert net.connected_ips == ("8.8.8.8", "8.8.4.4")
    be0 = PinnedBackend({"a.example.invalid": ("8.8.8.8",)}, net, max_attempts=0)
    with pytest.raises(PinViolation):
        await be0.connect_tcp("a.example.invalid", 443)
