"""egress_guard: 公開面の ASGI ミドルウェア。全パス共通で、1分あたりのリクエスト数と応答の転送量に上限をかける（設計 §6-3）。

枠や予算（quota.py）とは別の、最後の防波堤。インスタンス単位（Cloud Run の最大インスタンス数で全体の上限が決まる）。
  * リクエスト数（GUARD_LIMITS.requests_per_min）を超えた要求は、アプリへ渡さず 429。
  * 応答の本文の転送量（GUARD_LIMITS.egress_bytes_per_min）を超えた後の新しい要求は 503。流れている応答は止めない
    （SSE の途中で切ると精算が乱れる。次の要求から断る）。
  * 窓は直近60秒の固定窓（時計は注入できる）。利用者ごとのキー（IP 等）は作らない。
"""
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from app.config import GUARD_LIMITS, GuardLimits

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

WINDOW_S = 60.0


class EgressGuard:
    def __init__(self, app: ASGIApp, *, limits: GuardLimits = GUARD_LIMITS, clock: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.limits = limits
        self.clock = clock
        self._window_start = clock()
        self.requests = 0
        self.bytes_out = 0

    def _roll(self) -> None:
        now = self.clock()
        if now - self._window_start >= WINDOW_S:
            self._window_start, self.requests, self.bytes_out = now, 0, 0

    async def _reject(self, send: Send, status: int) -> None:
        body = b'{"ok":false,"code":"RATE_LIMITED"}'
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"retry-after", b"60"), (b"cache-control", b"no-store")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        self._roll()
        self.requests += 1
        if self.requests > self.limits.requests_per_min:
            await self._reject(send, 429)
            return
        if self.bytes_out >= self.limits.egress_bytes_per_min:
            await self._reject(send, 503)
            return

        async def counting_send(message: Message) -> None:
            if message.get("type") == "http.response.body":
                self._roll()
                self.bytes_out += len(message.get("body", b""))
            await send(message)

        await self.app(scope, receive, counting_send)
