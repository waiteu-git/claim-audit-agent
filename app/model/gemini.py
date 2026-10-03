"""GeminiPort: Vertex AI の Gemini を呼ぶ ModelPort（google-genai。ADC で認証し、API キーは使わない）。

location / model は環境変数（config.Settings）から渡す。自動の関数呼び出しは無効にし、
どのツールを呼べるかは呼び出しごとに Governor が決める（allowed_tool_names → mode=ANY）。

【実測の状態】（設計 §3・§6-1 が求めた「thinking の設定名」と「usage に thoughts が含まれるか」）
- 未実測。実行環境に GOOGLE_CLOUD_PROJECT が無く、Vertex を呼べなかった（プロジェクト ID を探しに行かない規則）。
  実測は `python -m ops.measure_gemini`（GOOGLE_CLOUD_PROJECT を渡して最大8回・短い出力）で取り、
  結果をこの節へ書き戻すこと。実測するまで下の SDK 定義からの推測で組んである。
- SDK（google-genai 2.27.0）の定義から分かること（実モデルの挙動ではない）:
  * ThinkingConfig は thinking_budget（int）と thinking_level（MINIMAL/LOW/MEDIUM/HIGH）の両方を持つ。
    gemini-3.7-flash がどちらを受けるかは未確認。既定は thinking_budget（設計の「Reader 1,024／Planner 512」）で、
    拒否されたら thinking_param="thinking_level" に切り替える（予算→水準の写像は _budget_to_level）。
  * usage_metadata は candidates_token_count と thoughts_token_count を別フィールドで持つ。
    thoughts が candidates に含まれるかは未確認のため、Usage.tokens_out は「足す」（候補＋thoughts）。
    もし candidates が thoughts を既に含むなら二重計上＝安全側（過大見積り）に倒れる。実測で確定する。
"""
import asyncio
import time
from collections.abc import Callable
from typing import Any, Literal

from google.genai import types

from app.config import Settings
from app.contracts import (
    FunctionCall,
    ModelRequest,
    ModelResponse,
    Usage,
    llm_json_schema,
)
from app.errors import AppError, ErrorCode, classify

ThinkingParam = Literal["thinking_budget", "thinking_level"]


def _budget_to_level(budget: int) -> types.ThinkingLevel:
    """thinking_level 方式へ切り替えた時の写像（未実測の暫定。実測後に見直す）。"""
    if budget <= 0:
        return types.ThinkingLevel.MINIMAL
    if budget <= 512:
        return types.ThinkingLevel.LOW
    if budget <= 2048:
        return types.ThinkingLevel.MEDIUM
    return types.ThinkingLevel.HIGH


def usage_from_metadata(meta: Any) -> Usage:
    """usage_metadata → Usage。欠けた欄（None）は 0。tokens_out は Usage 側の定義（候補＋thoughts＋tool_use）。"""
    if meta is None:
        return Usage()
    return Usage(
        prompt_tokens=meta.prompt_token_count or 0,
        candidates_tokens=meta.candidates_token_count or 0,
        thoughts_tokens=meta.thoughts_token_count or 0,
        tool_use_prompt_tokens=meta.tool_use_prompt_token_count or 0,
        cached_tokens=meta.cached_content_token_count or 0,
    )


class GeminiPort:
    """Vertex AI の Gemini 1モデル分。client はテストで差し替えられる（既定は初回呼び出しで作る）。"""

    def __init__(
        self,
        *,
        model_id: str,
        project: str | None = None,
        location: str = "global",
        client: Any | None = None,
        thinking_param: ThinkingParam = "thinking_budget",
        kill_switch: Callable[[], bool] = lambda: False,
    ) -> None:
        self._model_id = model_id
        self._project = project
        self._location = location
        self._client = client
        self._thinking_param = thinking_param
        self._kill_switch = kill_switch

    @classmethod
    def from_settings(cls, settings: Settings, *, model_id: str, client: Any | None = None) -> "GeminiPort":
        return cls(
            model_id=model_id,
            project=settings.google_cloud_project,
            location=settings.gemini_location,
            client=client,
            kill_switch=lambda: settings.kill_switch,
        )

    @property
    def model_id(self) -> str:
        return self._model_id

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._project:
                raise AppError(ErrorCode.FATAL_CONFIG, "GOOGLE_CLOUD_PROJECT が未設定")
            from google import genai

            # vertexai=True を明示（GOOGLE_API_KEY 等の環境変数があっても API キー経路へ行かない）
            self._client = genai.Client(vertexai=True, project=self._project, location=self._location)
        return self._client

    def build_config(self, request: ModelRequest) -> types.GenerateContentConfig:
        """ModelRequest → SDK の設定。ネットワークに触れない（テストで内容を検査できる）。"""
        kwargs: dict[str, Any] = {
            "system_instruction": request.system,
            "temperature": request.temperature,
            "max_output_tokens": request.max_output_tokens,
            # SDK 側の自動再試行は止める（attempts=1）。再試行は RetryingPort だけが行い、呼び出し数の計上とずれないように。
            "http_options": types.HttpOptions(
                timeout=int(request.timeout_s * 1000), retry_options=types.HttpRetryOptions(attempts=1)
            ),
            "automatic_function_calling": types.AutomaticFunctionCallingConfig(disable=True),
        }
        if request.thinking_budget is not None:
            if self._thinking_param == "thinking_level":
                kwargs["thinking_config"] = types.ThinkingConfig(thinking_level=_budget_to_level(request.thinking_budget))
            else:
                kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=request.thinking_budget)
        if request.response_model is not None:
            kwargs["response_mime_type"] = "application/json"
            kwargs["response_json_schema"] = llm_json_schema(request.response_model)
        if request.tools:
            kwargs["tools"] = [
                types.Tool(
                    function_declarations=[
                        types.FunctionDeclaration(
                            name=t.name.value, description=t.description, parameters_json_schema=t.parameters
                        )
                        for t in request.tools
                    ]
                )
            ]
            kwargs["tool_config"] = types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode=types.FunctionCallingConfigMode.ANY,  # 必ず関数を呼ばせる（自由文の脱出路を作らない）
                    allowed_function_names=[n.value for n in request.allowed_tool_names],
                )
            )
        return types.GenerateContentConfig(**kwargs)

    def to_response(self, resp: Any, latency_ms: int) -> ModelResponse:
        """SDK の応答 → ModelResponse。thought パートは text に混ぜない。"""
        cand = resp.candidates[0] if getattr(resp, "candidates", None) else None
        texts: list[str] = []
        calls: list[FunctionCall] = []
        if cand is not None and cand.content is not None:
            for part in cand.content.parts or []:
                if part.function_call is not None:
                    calls.append(FunctionCall(name=part.function_call.name or "", args=dict(part.function_call.args or {})))
                elif part.text and not part.thought:
                    texts.append(part.text)
        reason = cand.finish_reason.name if cand is not None and cand.finish_reason is not None else "NO_CANDIDATE"
        return ModelResponse(
            model=self._model_id,
            text="".join(texts) if texts else None,
            function_calls=tuple(calls),
            usage=usage_from_metadata(getattr(resp, "usage_metadata", None)),
            finish_reason=reason,
            latency_ms=latency_ms,
        )

    async def generate(self, request: ModelRequest) -> ModelResponse:
        if self._kill_switch():
            raise AppError(ErrorCode.KILLED, "KILL_SWITCH")
        config = self.build_config(request)
        client = self._get_client()
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(
                client.aio.models.generate_content(model=self._model_id, contents=request.contents, config=config),
                timeout=request.timeout_s,
            )
        except asyncio.CancelledError:
            raise
        except AppError:
            raise
        except Exception as e:
            # 例外の本文は非公開ログ用の detail に閉じ込め、公開面には ErrorCode だけが出る（errors.py）
            raise AppError(classify(e), f"{type(e).__name__}: {e}") from e
        return self.to_response(resp, int((time.monotonic() - t0) * 1000))
