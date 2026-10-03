"""SafeFetch のテスト用フェイク（完全オフライン）。

  FakeResolver … 名前解決の注入先。呼び出し回数を数え、「呼び出しごとの応答」を並べられる（DNS リバインディングの再現）。
  FakeInternet … httpcore のネットワーク層の差し替え。接続先（IP）・TLS の server_hostname・受けたリクエストを記録し、
                 Host ヘッダと対象パスで偽のサイト（vectors.Reply）を選んで HTTP/1.1 の応答を返す。実際のソケットは開かない。

実ネットワークは使わない。ループバックの実 TLS で SNI・証明書検証まで確かめる試験は test_safefetch_tls.py。
"""
import asyncio
import ipaddress
import ssl
import zlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus

import httpcore

from app.config import FETCH_LIMITS, FetchLimits
from app.net.safefetch import SafeFetch
from app.net.vectors import DEFAULT_DNS, VECTOR_PREFIXES, Reply

# fake の start_tls は使わないので、何も読み込まない軽い文脈（毎回 CA を読むと遅い）。
FAKE_SSL = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

_CHUNK = 16 * 1024


class FakeResolver:
    """host → 「呼び出し回数ごとの応答」の並び。最後の応答はそれ以降も続く。未登録のホストは名前解決の失敗。"""

    def __init__(self, dns: Mapping[str, Sequence[Sequence[str]]] | None = None) -> None:
        self.dns = {**DEFAULT_DNS, **(dns or {})}
        self.calls: dict[str, int] = {}

    async def __call__(self, host: str) -> list[str]:
        n = self.calls.get(host, 0)
        self.calls[host] = n + 1
        answers = self.dns.get(host)
        if answers is None:
            raise OSError("fake NXDOMAIN")
        return list(answers[min(n, len(answers) - 1)])


@dataclass
class SeenRequest:
    ip: str  # 接続先として渡された値（検査済み IP のはず）
    tls_hostname: str | None  # start_tls の server_hostname（SNI・証明書検証に使われる名前）
    method: str
    target: str
    headers: dict[str, str]  # 小文字キー


@dataclass
class _Plan:
    items: Iterator[tuple[float, bytes]]


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Status"


def _body_pieces(reply: Reply) -> Iterator[bytes]:
    if reply.repeat is not None:
        piece, times = reply.repeat
        for _ in range(times):
            yield piece
    elif reply.body:
        yield reply.body


def _encoded_body(reply: Reply) -> bytes:
    if not reply.gzip:
        return b"".join(_body_pieces(reply))
    comp = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    out = [comp.compress(p) for p in _body_pieces(reply)]
    out.append(comp.flush())
    return b"".join(out)


def _infinite(reply: Reply) -> Iterator[tuple[float, bytes]]:
    assert reply.infinite is not None
    if reply.prefix:
        yield reply.chunk_delay_s, b"%x\r\n" % len(reply.prefix) + reply.prefix + b"\r\n"
    framed = b"%x\r\n" % len(reply.infinite) + reply.infinite + b"\r\n"
    while True:
        yield reply.chunk_delay_s, framed


def build_plan(reply: Reply) -> _Plan:
    """Reply → HTTP/1.1 の応答（先頭の項目が status 行＋ヘッダ。以降が本文の塊。(待ち秒, バイト列) の列）。"""
    headers = [*reply.headers, ("Connection", "close")]
    if reply.infinite is not None:
        headers.append(("Transfer-Encoding", "chunked"))
        body_items: Iterator[tuple[float, bytes]] = _infinite(reply)
    elif reply.chunked:
        headers.append(("Transfer-Encoding", "chunked"))
        encoded = _encoded_body(reply)
        size = max(reply.chunk_size, 1)
        ext = b";" + b"x" * reply.chunk_ext if reply.chunk_ext else b""
        pieces = [encoded[i : i + size] for i in range(0, len(encoded), size)]
        body_items = iter(
            [(reply.chunk_delay_s, b"%x" % len(p) + ext + b"\r\n" + p + b"\r\n") for p in pieces] + [(0.0, b"0\r\n\r\n")]
        )
    else:
        encoded = _encoded_body(reply)
        length = reply.content_length if reply.content_length is not None else len(encoded)
        headers.append(("Content-Length", str(length)))
        body_items = iter(
            [(reply.chunk_delay_s, encoded[i : i + _CHUNK]) for i in range(0, len(encoded), _CHUNK)]
        )
    head = f"HTTP/1.1 {reply.status} {_reason(reply.status)}\r\n".encode("latin-1")
    head += b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in headers) + b"\r\n"

    def items() -> Iterator[tuple[float, bytes]]:
        for _ in range(reply.informational):  # 本物の応答の前の 1xx（h11 は1つずつ読み捨てる）
            yield 0.0, b"HTTP/1.1 100 Continue\r\n\r\n"
        yield reply.first_byte_delay_s, head
        yield from body_items

    return _Plan(items())


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, net: "FakeInternet", ip: str) -> None:
        self._net = net
        self._ip = ip
        self._tls_hostname: str | None = None
        self._written = b""
        self._plan: Iterator[tuple[float, bytes]] | None = None
        self._rest = b""

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self._plan is None:
            raise httpcore.ReadError("fake: リクエスト前の read")
        if not self._rest:
            try:
                delay, data = next(self._plan)
            except StopIteration:
                return b""  # EOF
            if delay:
                if timeout is not None and delay > timeout:  # 実ソケットと同じく、待ち切れずに ReadTimeout
                    await asyncio.sleep(timeout)
                    raise httpcore.ReadTimeout("fake")
                await asyncio.sleep(delay)
            self._rest = data
        out, self._rest = self._rest[:max_bytes], self._rest[max_bytes:]
        return out

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._written += buffer
        if self._plan is None and b"\r\n\r\n" in self._written:
            head, _, _ = self._written.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _version = lines[0].split(" ")
            headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
            self._net.requests.append(
                SeenRequest(ip=self._ip, tls_hostname=self._tls_hostname, method=method, target=target, headers=headers)
            )
            self._plan = self._net.select(headers.get("host", ""), target).items

    async def aclose(self) -> None:
        return None

    async def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> "FakeStream":
        self._tls_hostname = server_hostname
        return self

    def get_extra_info(self, info: str):  # noqa: ANN201
        return None


class FakeInternet(httpcore.AsyncNetworkBackend):
    """routes は "host/path?query" → Reply。無い所は 404。"""

    def __init__(
        self,
        routes: Mapping[str, Reply] | None = None,
        *,
        connect_errors: Mapping[str, Exception] | None = None,
    ) -> None:
        self.routes = dict(routes or {})
        self.connect_errors = dict(connect_errors or {})
        self.connects: list[tuple[str, int]] = []
        self.non_ip_connects: list[str] = []  # 名前（IP でないもの）で接続しようとした＝ピン留めの破れ
        self.requests: list[SeenRequest] = []
        self.unrouted: list[str] = []

    def select(self, host: str, target: str) -> _Plan:
        reply = self.routes.get(f"{host}{target}")
        if reply is None:
            self.unrouted.append(f"{host}{target}")
            reply = Reply(status=404, body=b"<html>not found</html>")
        return build_plan(reply)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,  # noqa: ANN001
    ) -> FakeStream:
        self.connects.append((host, port))
        try:
            ipaddress.ip_address(host)
        except ValueError:
            self.non_ip_connects.append(host)
        err = self.connect_errors.get(host)
        if err is not None:
            raise err
        return FakeStream(self, host)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # type: ignore[no-untyped-def]  # noqa: ANN001
        raise AssertionError("UNIX ソケットへの接続は起きてはいけない")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    @property
    def connected_ips(self) -> tuple[str, ...]:
        return tuple(h for h, _ in self.connects)


@dataclass
class Rig:
    fetch: SafeFetch
    resolver: FakeResolver
    net: FakeInternet
    limits: FetchLimits = field(default=FETCH_LIMITS)


def make_rig(
    routes: Mapping[str, Reply] | None = None,
    *,
    dns: Mapping[str, Sequence[Sequence[str]]] | None = None,
    prefixes=VECTOR_PREFIXES,  # noqa: ANN001
    limits: FetchLimits = FETCH_LIMITS,
    connect_errors: Mapping[str, Exception] | None = None,
) -> Rig:
    resolver = FakeResolver(dns)
    net = FakeInternet(routes, connect_errors=connect_errors)
    sf = SafeFetch(prefixes, limits=limits, resolver=resolver, network_backend=net, ssl_context=FAKE_SSL)
    return Rig(fetch=sf, resolver=resolver, net=net, limits=limits)
