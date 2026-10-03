"""再試行（設計 §3 RUN_CAPS）。429/5xx/タイムアウトだけ、最大 N 回、1s→8s のバックオフ、壁時計の内側で。

QUOTA（自前の枠）・FATAL_CONFIG・KILLED・SCHEMA_VIOLATION は再試行しない。
"""
import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence

from app.contracts import ModelRequest, ModelResponse
from app.errors import AppError, ErrorCode, classify, is_retryable
from app.model.port import ModelPort


class RetryingPort:
    def __init__(
        self,
        inner: ModelPort,
        *,
        retries: int,
        backoff_s: Sequence[float],
        deadline_monotonic: float | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        on_retry: Callable[[int, ErrorCode, float], None] | None = None,
    ) -> None:
        if not backoff_s:
            raise ValueError("backoff_s は1つ以上")
        self._inner = inner
        self._retries = retries
        self._backoff = tuple(backoff_s)
        self._deadline = deadline_monotonic  # 壁時計の締切（これを超える待ちはしない）
        self._sleep = sleep
        self._clock = clock
        self._on_retry = on_retry

    @property
    def model_id(self) -> str:
        return self._inner.model_id

    async def generate(self, request: ModelRequest) -> ModelResponse:
        attempt = 0
        while True:
            try:
                return await self._inner.generate(request)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                code = classify(e)
                delay = self._backoff[min(attempt, len(self._backoff) - 1)]
                out_of_time = self._deadline is not None and self._clock() + delay >= self._deadline
                if not is_retryable(code) or attempt >= self._retries or out_of_time:
                    if isinstance(e, AppError):
                        raise
                    raise AppError(code, f"{type(e).__name__}: {e}") from e
                attempt += 1
                if self._on_retry is not None:
                    self._on_retry(attempt, code, delay)
                await self._sleep(delay)
