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
    except json.JSONDecodeError as e:
        raise AppError(ErrorCode.SCHEMA_VIOLATION, f"{model_cls.__name__} に合わない出力") from e
    except ValidationError as e:
        clipped = _clip_overlong_top_lists(response.text, e)
        if clipped is None:
            raise AppError(ErrorCode.SCHEMA_VIOLATION, f"{model_cls.__name__} に合わない出力") from e
        try:
            return model_cls.model_validate(clipped)
        except ValidationError as e2:
            raise AppError(ErrorCode.SCHEMA_VIOLATION, f"{model_cls.__name__} に合わない出力") from e2


def _clip_overlong_top_lists(text: str, err: ValidationError) -> dict | None:
    """違反が「最上位のリストの件数超過」だけなら、先頭から上限までに切り詰めた dict を返す。それ以外は None。

    Vertex は構造化出力スキーマの maxItems を 400 で拒否する（2026-10-07 実測）ため、スキーマから外して送っている。
    その結果モデルが上限を知らずに多く返すと、1チャンク丸ごとが捨てられていた（gemini-2.5-flash の実LPで発生）。
    件数超過だけは切り詰めて受け入れ、ほかの違反（型・欄の過不足・長さ）はこれまでどおり拒否する。
    （app.model は jsonlog に依存しない決まり＝ここではログを出さない。切り詰めは上限件数の到達として結果に表れる）
    """
    errors = err.errors()
    if not errors or any(x.get("type") != "too_long" or len(x.get("loc", ())) != 1 for x in errors):
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    for x in errors:
        key = x["loc"][0]
        limit = (x.get("ctx") or {}).get("max_length")
        if not isinstance(data.get(key), list) or not isinstance(limit, int):
            return None
        data[key] = data[key][:limit]
    return data
