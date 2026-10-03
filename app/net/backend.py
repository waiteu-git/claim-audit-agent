"""PinnedBackend: 検査済みの IP にだけ接続する httpcore のネットワーク層（設計 §5-3 接続ピン留め）。

仕組み: SafeFetch が GuardedResolver で解決・検査した IP を `pins[host]` に入れ、この層は
  * pins に無いホストへの接続を拒否する（この層は名前解決を一切しない＝再解決でリバインディングされない）
  * 接続は IP リテラルで行う（内側のバックエンドは名前を引かない）
  * TLS の SNI・証明書検証・Host ヘッダは httpcore が元のホスト名で行う（start_tls の server_hostname は
    URL のホストが入る。IP に接続しても検証を弱めない）
内側のバックエンド（inner）は注入できる。本番は httpcore.AnyIOBackend、テストはフェイク。

もう1つの役目: 受信した全バイト数の計量（WireMeter）。本文の上限（展開後 1MiB・生の受信 3MB）は「本文のバイト数」しか
数えないので、1xx の洪水・chunk-extension の肥大・1バイトずつの塊のような「本文に数えられない受信」が上限をすり抜け、
1回の取得でイベントループを使い切れた（敵対レビューの実測: CPU 5〜8 秒）。TLS の内側（HTTP のバイト列）で数える。
"""
import time

import httpcore

from app.net.resolver import DEFAULT_MAX_ADDRESSES_TRIED


class PinViolation(Exception):
    """pins に無いホスト・443 以外・UNIX ソケットへの接続要求。コードの誤りか攻撃で、起きたら止める。"""


class WireBudgetExceeded(Exception):
    """受信したバイト数が、その段階（head＝応答の先頭を受け終えるまで／body＝本文）の予算を超えた。"""

    def __init__(self, phase: str) -> None:
        super().__init__(f"wire.{phase}")
        self.phase = phase


class WireMeter:
    """1回の取得（転送を含む）で、socket から読んだバイト数を数え、段階ごとの予算を超えたら止める。

    arm() が呼ばれるまでは無制限（PinnedBackend 単体の利用・テスト用）。SafeFetch は各ホップの前に head、
    応答の先頭を受け終えた直後に body を arm する（予算はその時点からの増分で、ホップごとに引き直す）。
    """

    def __init__(self) -> None:
        self.total = 0
        self._limit: int | None = None
        self.phase = "head"

    def arm(self, budget: int, phase: str) -> None:
        self.phase = phase
        self._limit = self.total + budget

    def add(self, n: int) -> None:
        self.total += n
        if self._limit is not None and self.total > self._limit:
            raise WireBudgetExceeded(self.phase)


class _CountingStream(httpcore.AsyncNetworkStream):
    """読んだバイト数を meter に渡す。start_tls の後の（暗号を外した）ストリームも同じ meter で包む。"""

    def __init__(self, inner: httpcore.AsyncNetworkStream, meter: WireMeter) -> None:
        self._inner = inner
        self._meter = meter

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        data = await self._inner.read(max_bytes, timeout=timeout)
        self._meter.add(len(data))
        return data

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self, ssl_context, server_hostname: str | None = None, timeout: float | None = None  # noqa: ANN001
    ) -> "_CountingStream":
        tls = await self._inner.start_tls(ssl_context, server_hostname=server_hostname, timeout=timeout)
        return _CountingStream(tls, self._meter)

    def get_extra_info(self, info: str):  # noqa: ANN201
        return self._inner.get_extra_info(info)


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        pins: dict[str, tuple[str, ...]],
        inner: httpcore.AsyncNetworkBackend,
        *,
        max_attempts: int = DEFAULT_MAX_ADDRESSES_TRIED,
        meter: WireMeter | None = None,
    ) -> None:
        self._pins = pins  # SafeFetch が1回の取得ごとに作る。ホップごとに検査済みの IP を足す
        self._inner = inner
        self._max_attempts = max_attempts
        self._meter = meter  # 受信バイトの計量（None なら数えない）

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,  # noqa: ANN001 httpcore の型に合わせる
    ) -> httpcore.AsyncNetworkStream:
        ips = self._pins.get(host)
        if not ips or port != 443:
            raise PinViolation("pin.missing")
        started = time.monotonic()
        last: Exception | None = None
        for ip in ips[: self._max_attempts]:
            remaining = None if timeout is None else max(timeout - (time.monotonic() - started), 0.001)
            try:
                stream = await self._inner.connect_tcp(
                    ip, port, timeout=remaining, local_address=None, socket_options=socket_options
                )
                return stream if self._meter is None else _CountingStream(stream, self._meter)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:  # 次の検査済み IP を試す
                last = e
        raise last if last is not None else PinViolation("pin.no_attempt")  # max_attempts<=0 の誤設定でも接続しない

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # type: ignore[no-untyped-def]  # noqa: ANN001
        raise PinViolation("pin.unix_socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)
