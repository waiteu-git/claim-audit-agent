"""壁時計の内側に収めるモデル呼び出し（WallBoundPort）。

壁時計（Governor・BudgetMeter）は「呼び出しを始める時」にしか見ない協調式の仕組みで、実行中の呼び出しは打ち切らない。
モデルの応答が遅い時間帯（単発の呼び出しが 5〜28 秒）には、上限の直前に始めた呼び出しの応答を待ち続けて、実行の外側の期限
（web の run_timeout_s）に当たる。その場合は費用が分からず、予約の最悪値（既定 ¥50。実際は ¥2〜10）で精算されてしまい、
遅い時間帯に日次の円の上限が数回で尽きる（10/8 の敵対レビュー）。

ここで1回の呼び出しの待ちを「壁時計の締切＋少しの余裕」までに収めると、協調式の中断（WALL_CLOCK）が先に起き、
Governor が実際に使った分で精算でき、web は保存済みの実行へ切り替えられる。外側の期限は、取得など、モデル以外で固まった時の備えに残る。
"""
import asyncio
import time
from collections.abc import Callable

from app.contracts import ModelRequest, ModelResponse
from app.model.port import ModelPort


class WallBoundPort:
    """inner の generate を、締切（deadline_monotonic）＋ slack_s までで打ち切る。締切を過ぎてからは、呼び出しを始めない。

    打ち切りは TimeoutError（errors.classify で RETRYABLE。再試行は RetryingPort が締切で止める）。
    CancelledError は呑み込まない（切断・外側の期限の取り消しをそのまま通す）。
    """

    def __init__(
        self,
        inner: ModelPort,
        *,
        deadline_monotonic: float,
        slack_s: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if slack_s < 0:
            raise ValueError("slack_s は 0 以上")
        self._inner = inner
        self._deadline = deadline_monotonic
        self._slack = slack_s
        self._clock = clock

    @property
    def model_id(self) -> str:
        return self._inner.model_id

    async def generate(self, request: ModelRequest) -> ModelResponse:
        remaining = self._deadline + self._slack - self._clock()
        if remaining <= 0:
            raise TimeoutError("壁時計の上限を過ぎています")  # 始めない（費用もかからない）
        async with asyncio.timeout(remaining):
            return await self._inner.generate(request)
