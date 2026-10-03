"""GeminiPort: 設定の組み立て・応答の写し・トークン計数・エラー分類（すべてオフライン。client はフェイク）。"""
import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from google.genai import errors as genai_errors
from google.genai import types

import app.contracts as C
from app.config import RUN_CAPS, load_settings
from app.errors import AppError, ErrorCode
from app.model.gemini import GeminiPort, _budget_to_level, usage_from_metadata
from app.model.port import ModelPort
from tests.factories import planner_request, reader_request


def response(parts: list[types.Part], usage: types.GenerateContentResponseUsageMetadata | None = None, finish=types.FinishReason.STOP):
    return types.GenerateContentResponse(
        candidates=[types.Candidate(content=types.Content(role="model", parts=parts), finish_reason=finish)],
        usage_metadata=usage,
    )


class FakeClient:
    """client.aio.models.generate_content(model=, contents=, config=) だけを持つフェイク。"""

    def __init__(self, result: Any = None, delay: float = 0.0) -> None:
        self.calls: list[dict[str, Any]] = []
        outer = self

        class Models:
            async def generate_content(self, **kw: Any) -> Any:
                outer.calls.append(kw)
                if delay:
                    await asyncio.sleep(delay)
                if isinstance(outer.result, BaseException):
                    raise outer.result
                return outer.result

        self.result = result
        self.aio = SimpleNamespace(models=Models())


def port(client: FakeClient, **kw: Any) -> GeminiPort:
    return GeminiPort(model_id="gemini-3.7-flash", client=client, **kw)


# --- トークン計数（§6-1: tokens_out = candidates + thoughts） ---------------------------
def test_tokens_out_counts_thoughts_from_a_fixed_usage_metadata():
    meta = types.GenerateContentResponseUsageMetadata(
        prompt_token_count=1000, candidates_token_count=200, thoughts_token_count=700, total_token_count=1900
    )
    u = usage_from_metadata(meta)
    assert (u.tokens_in, u.candidates_tokens, u.thoughts_tokens, u.tokens_out) == (1000, 200, 700, 900)
    # 既存 /probe は candidates だけを数えて 200 としていた（thinking の分が課金から落ちる）
    assert u.tokens_out != meta.candidates_token_count


def test_tokens_out_includes_tool_use_prompt_tokens_when_present():
    meta = types.GenerateContentResponseUsageMetadata(
        prompt_token_count=10, candidates_token_count=5, thoughts_token_count=7, tool_use_prompt_token_count=3, cached_content_token_count=4
    )
    u = usage_from_metadata(meta)
    assert u.tokens_out == 15 and u.cached_tokens == 4


def test_missing_usage_fields_count_as_zero():
    assert usage_from_metadata(None).tokens_out == 0
    assert usage_from_metadata(types.GenerateContentResponseUsageMetadata(prompt_token_count=5)).tokens_out == 0


# --- 応答の写し --------------------------------------------------------------------
async def test_text_response_skips_thought_parts_and_reports_usage():
    resp = response(
        [types.Part(text="内部の思考", thought=True), types.Part(text='{"page_class":"content",'), types.Part(text='"requirements":[]}')],
        types.GenerateContentResponseUsageMetadata(prompt_token_count=120, candidates_token_count=30, thoughts_token_count=300),
    )
    out = await port(FakeClient(resp)).generate(reader_request())
    assert out.text == '{"page_class":"content","requirements":[]}' and "思考" not in out.text
    assert (out.usage.tokens_in, out.usage.tokens_out) == (120, 330)
    assert out.finish_reason == "STOP" and out.model == "gemini-3.7-flash" and out.latency_ms >= 0 and not out.function_calls
    assert isinstance(port(FakeClient(resp)), ModelPort)


async def test_function_call_response_becomes_raw_function_calls():
    resp = response([types.Part(function_call=types.FunctionCall(name="fetch_link", args={"link_id": "L9", "reason": "x"}))])
    out = await port(FakeClient(resp)).generate(planner_request())
    assert out.text is None and out.function_calls == (C.FunctionCall(name="fetch_link", args={"link_id": "L9", "reason": "x"}),)


async def test_no_candidates_is_reported_not_crashed():
    out = await port(FakeClient(types.GenerateContentResponse(candidates=[]))).generate(reader_request())
    assert out.text is None and out.finish_reason == "NO_CANDIDATE"
    out = await port(FakeClient(response([types.Part(text="x")], finish=types.FinishReason.MAX_TOKENS))).generate(reader_request())
    assert out.finish_reason == "MAX_TOKENS"


# --- 設定の組み立て（ネットワークに触れない） ---------------------------------------------
def test_reader_config_forces_schema_and_never_has_tools():
    cfg = port(FakeClient()).build_config(reader_request())
    assert cfg.thinking_config.thinking_budget == RUN_CAPS.thinking_budget_reader
    assert cfg.response_mime_type == "application/json" and cfg.tools is None and cfg.tool_config is None
    assert "$ref" not in str(cfg.response_json_schema) and cfg.response_json_schema["type"] == "object"
    assert cfg.automatic_function_calling.disable is True
    assert cfg.temperature == 0.0 and cfg.max_output_tokens == 1000 and cfg.system_instruction == "sys"
    assert cfg.http_options.timeout == 25_000
    assert cfg.http_options.retry_options.attempts == 1  # SDK の隠れた再試行で呼び出し数の計上がずれない


def test_planner_config_allows_only_the_governors_function_names_and_disables_auto_calling():
    cfg = port(FakeClient()).build_config(planner_request())
    fc = cfg.tool_config.function_calling_config
    assert fc.mode == types.FunctionCallingConfigMode.ANY and fc.allowed_function_names == ["finish"]
    assert [d.name for d in cfg.tools[0].function_declarations] == ["finish"]
    assert cfg.response_json_schema is None and cfg.response_mime_type is None
    assert cfg.automatic_function_calling.disable is True
    assert cfg.thinking_config.thinking_budget == 512


def test_no_thinking_config_when_the_request_has_no_budget():
    cfg = port(FakeClient()).build_config(reader_request(thinking_budget=None))
    assert cfg.thinking_config is None
    assert port(FakeClient()).build_config(reader_request(thinking_budget=0)).thinking_config.thinking_budget == 0


def test_thinking_level_mode_maps_budgets_to_levels():
    p = port(FakeClient(), thinking_param="thinking_level")
    cfg = p.build_config(reader_request(thinking_budget=512))
    assert cfg.thinking_config.thinking_level == types.ThinkingLevel.LOW and cfg.thinking_config.thinking_budget is None
    assert [_budget_to_level(b).name for b in (0, 512, 1024, 4096)] == ["MINIMAL", "LOW", "MEDIUM", "HIGH"]


# --- 呼び出し ----------------------------------------------------------------------
async def test_generate_passes_model_contents_and_config_to_the_client():
    client = FakeClient(response([types.Part(text="{}")]))
    await port(client).generate(reader_request(contents="本文"))
    call = client.calls[0]
    assert call["model"] == "gemini-3.7-flash" and call["contents"] == "本文" and isinstance(call["config"], types.GenerateContentConfig)


async def test_kill_switch_blocks_before_any_client_is_created():
    client = FakeClient(response([types.Part(text="{}")]))
    p = port(client, kill_switch=lambda: True)
    with pytest.raises(AppError) as ei:
        await p.generate(reader_request())
    assert ei.value.code is ErrorCode.KILLED and client.calls == []


async def test_kill_switch_from_settings_is_checked_on_every_call():
    s = load_settings({"KILL_SWITCH": "1"})
    client = FakeClient(response([types.Part(text="{}")]))
    with pytest.raises(AppError):
        await GeminiPort.from_settings(s, model_id="m", client=client).generate(reader_request())
    s = load_settings({"GOOGLE_CLOUD_PROJECT": "p", "GEMINI_LOCATION": "asia-northeast1"})
    p = GeminiPort.from_settings(s, model_id="m", client=client)
    assert (p._project, p._location, p.model_id) == ("p", "asia-northeast1", "m")


async def test_missing_project_is_a_fatal_config_error_without_touching_the_network():
    p = GeminiPort(model_id="m", project=None)  # client 無し・project 無し
    with pytest.raises(AppError) as ei:
        await p.generate(reader_request())
    assert ei.value.code is ErrorCode.FATAL_CONFIG


@pytest.mark.parametrize(
    "exc,code",
    [
        (genai_errors.ServerError(503, {"error": {"message": "overloaded"}}), ErrorCode.RETRYABLE),
        (genai_errors.ClientError(429, {"error": {"message": "slow down"}}), ErrorCode.RETRYABLE),
        (genai_errors.ClientError(404, {"error": {"message": "model not found"}}), ErrorCode.FATAL_CONFIG),
        (genai_errors.ClientError(403, {"error": {"message": "denied"}}), ErrorCode.FATAL_CONFIG),
        (genai_errors.ClientError(400, {"error": {"message": "bad"}}), ErrorCode.FATAL_CONFIG),
        (ConnectionResetError("reset"), ErrorCode.RETRYABLE),
        (ValueError("weird"), ErrorCode.INTERNAL),
    ],
)
async def test_sdk_errors_are_classified_and_the_message_stays_private(exc, code):
    with pytest.raises(AppError) as ei:
        await port(FakeClient(exc)).generate(reader_request())
    assert ei.value.code is code and ei.value.__cause__ is exc
    assert "model not found" not in ei.value.public_message


async def test_per_call_timeout_becomes_retryable():
    with pytest.raises(AppError) as ei:
        await port(FakeClient(response([types.Part(text="{}")]), delay=0.5)).generate(reader_request(timeout_s=0.05))
    assert ei.value.code is ErrorCode.RETRYABLE


async def test_cancellation_passes_through():
    task = asyncio.create_task(port(FakeClient(response([types.Part(text="{}")]), delay=5)).generate(reader_request()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
