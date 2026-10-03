"""ModelPort（モデル呼び出しの境界）。Reader / Planner は実装（Gemini・台本・cassette）を知らずにこれだけを使う。

入出力の型（ModelRequest / ModelResponse）は app.contracts。
実装: gemini.GeminiPort（本番・Vertex）／scripted.ScriptedPort（テスト専用）／cassette.CassettePort（記録・再生）／
retry.RetryingPort（429/5xx の再試行）。
"""
import json
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

from app.contracts import ModelRequest, ModelResponse
from app.errors import AppError, ErrorCode

T = TypeVar("T", bound=BaseModel)


@runtime_checkable
class ModelPort(Protocol):
    """モデルを1回呼ぶ。失敗は AppError（code=RETRYABLE / QUOTA / FATAL_CONFIG / KILLED ほか）で投げる。"""

    @property
    def model_id(self) -> str: ...

    async def generate(self, request: ModelRequest) -> ModelResponse: ...


def parse_structured(response: ModelResponse, model_cls: type[T]) -> T:
    """Reader の text(JSON) を契約型へ。形式違反は AppError(SCHEMA_VIOLATION)。

    モデルの出力は非信頼なので extra=forbid の型で厳密に検証する。空・JSON 以外・欄の過不足はすべて拒否。
    """
    if not response.text:
        raise AppError(ErrorCode.SCHEMA_VIOLATION, "モデルの出力が空")
    try:
        return model_cls.model_validate_json(response.text)
    except (ValidationError, json.JSONDecodeError) as e:
        raise AppError(ErrorCode.SCHEMA_VIOLATION, f"{model_cls.__name__} に合わない出力") from e
