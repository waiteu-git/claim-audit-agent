"""ScriptedPort: 台本どおりに返すテスト専用の ModelPort。

本番の import 連鎖に入れない（ENV=public で import されていたら起動を拒否する。config.startup_violations）。
乗っ取られたモデル（存在しない link_id・23回目の呼び出し・全件適合の返答など）の再現に使う（設計 §5-2 試験）。
"""
import json
from collections import deque
from collections.abc import Callable, Iterable
from typing import Any

from pydantic import BaseModel

from app.contracts import FunctionCall, ModelRequest, ModelResponse, Usage

Step = ModelResponse | BaseException | Callable[[ModelRequest], ModelResponse]


class ScriptExhausted(AssertionError):
    """台本が尽きたのに呼び出された（想定より多く呼んでいる＝上限制御の不具合の疑い）。"""


def reply_json(
    obj: BaseModel | dict[str, Any] | str,
    *,
    tokens_in: int = 100,
    tokens_out: int = 50,
    thoughts: int = 0,
    model: str = "scripted-model",
    finish_reason: str = "STOP",
) -> ModelResponse:
    """Reader 用の応答（text=JSON）。"""
    if isinstance(obj, str):
        text = obj
    elif isinstance(obj, BaseModel):
        text = obj.model_dump_json()
    else:
        text = json.dumps(obj, ensure_ascii=False)
    return ModelResponse(
        model=model,
        text=text,
        usage=Usage(prompt_tokens=tokens_in, candidates_tokens=tokens_out, thoughts_tokens=thoughts),
        finish_reason=finish_reason,
    )


def reply_calls(
    *calls: tuple[str, dict[str, Any]],
    tokens_in: int = 100,
    tokens_out: int = 20,
    thoughts: int = 0,
    model: str = "scripted-model",
) -> ModelResponse:
    """Planner 用の応答（関数呼び出し）。名前・引数は検証前の生の値を入れてよい（乗っ取りの再現）。"""
    return ModelResponse(
        model=model,
        function_calls=tuple(FunctionCall(name=n, args=a) for n, a in calls),
        usage=Usage(prompt_tokens=tokens_in, candidates_tokens=tokens_out, thoughts_tokens=thoughts),
        finish_reason="STOP",
    )


class ScriptedPort:
    """steps を先頭から1つずつ消費する。Step は ModelResponse／投げる例外／ModelRequest→ModelResponse の関数。"""

    def __init__(self, steps: Iterable[Step], *, model_id: str = "scripted-model") -> None:
        self._steps: deque[Step] = deque(steps)
        self._model_id = model_id
        self.requests: list[ModelRequest] = []  # 受けた要求（Planner が何を見たかの検証用）

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def remaining(self) -> int:
        return len(self._steps)

    def assert_all_used(self) -> None:
        if self._steps:
            raise AssertionError(f"台本が {len(self._steps)} 手残っています")

    async def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if not self._steps:
            raise ScriptExhausted(f"{len(self.requests)} 回目の呼び出し。台本は尽きています")
        step = self._steps.popleft()
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, ModelResponse):
            return step
        return step(request)
