"""ops/measure_gemini.py: 実通信はせず、呼び出し回数の上限・失敗時の継続・解釈ロジックをフェイクで確かめる。"""
import json
from types import SimpleNamespace
from typing import Any

from google.genai import errors as genai_errors
from google.genai import types

from ops import measure_gemini as mg


class Meta:
    """usage_metadata の代役（model_dump と属性の両方を持つ）。"""

    def __init__(self, **kw: int) -> None:
        self._kw = kw
        for k in ("prompt_token_count", "candidates_token_count", "thoughts_token_count", "tool_use_prompt_token_count", "cached_content_token_count"):
            setattr(self, k, kw.get(k))

    def model_dump(self, **_: Any) -> dict[str, int]:
        return dict(self._kw)


def make_client(fail_on: dict[int, Exception] | None = None, usage: dict[str, int] | None = None):
    calls: list[dict[str, Any]] = []
    usage = usage or dict(prompt_token_count=100, candidates_token_count=10, thoughts_token_count=50, total_token_count=160)

    class Models:
        async def generate_content(self, **kw: Any) -> Any:
            n = len(calls)
            calls.append(kw)
            if fail_on and n in fail_on:
                raise fail_on[n]
            parts = [types.Part(text='{"page_class":"content","requirements":[]}')]
            if kw["config"].tool_config is not None:
                parts = [types.Part(function_call=types.FunctionCall(name="finish", args={}))]
            resp = types.GenerateContentResponse(
                candidates=[types.Candidate(content=types.Content(role="model", parts=parts), finish_reason=types.FinishReason.STOP)]
            )
            object.__setattr__(resp, "usage_metadata", Meta(**usage))
            return resp

    return SimpleNamespace(aio=SimpleNamespace(models=Models())), calls


async def test_runs_every_case_once_and_never_exceeds_the_cap():
    client, calls = make_client()
    rows = await mg.run_measurements(lambda: client, model_id="m", project="p", location="global")
    assert len(rows) == len(mg.CASES) <= mg.MAX_CALLS and len(calls) == len(rows)
    assert all(r["ok"] for r in rows)
    assert rows[0]["usage_raw"]["total_token_count"] == 160 and rows[0]["tokens_out_by_our_definition"] == 60
    assert "別" in rows[0]["usage_reading"]
    planner = next(r for r in rows if r["case"] == "planner_function_call_any")
    assert planner["function_calls"] == ["finish"]
    # 短い出力: すべてのケースで出力トークンの上限が小さい
    assert max(c["config"].max_output_tokens for c in calls) <= 512


async def test_max_calls_is_enforced_even_if_asked_for_more():
    client, calls = make_client()
    rows = await mg.run_measurements(lambda: client, model_id="m", project="p", location="global", max_calls=3)
    assert len(rows) == 3 == len(calls)


async def test_a_failing_case_is_recorded_with_code_only_and_the_run_continues():
    err = genai_errors.ClientError(400, {"error": {"message": "thinking_budget is not supported SECRET"}})
    client, calls = make_client(fail_on={1: err})
    rows = await mg.run_measurements(lambda: client, model_id="m", project="p", location="global")
    assert rows[1]["ok"] is False and rows[1]["error_code"] == "FATAL_CONFIG" and rows[1]["http_status"] == 400
    assert "SECRET" not in json.dumps(rows) and len(rows) == len(mg.CASES)


def test_interpret_usage():
    assert "別" in mg.interpret_usage(dict(prompt_token_count=10, candidates_token_count=5, thoughts_token_count=20, total_token_count=35))
    assert "含まれる" in mg.interpret_usage(dict(prompt_token_count=10, candidates_token_count=25, thoughts_token_count=20, total_token_count=35))
    assert "判定不能" in mg.interpret_usage(dict(prompt_token_count=10, candidates_token_count=5, thoughts_token_count=20, total_token_count=99))
    assert "判定不能" in mg.interpret_usage({})


def test_main_refuses_without_confirmation_or_project(capsys):
    assert mg.main([], {"GOOGLE_CLOUD_PROJECT": "p"}) == 2
    assert "--yes" in capsys.readouterr().err
    assert mg.main(["--yes"], {}) == 2
    assert "未実測" in capsys.readouterr().err


def test_main_prints_one_json_line_per_case(capsys):
    client, calls = make_client()
    assert mg.main(["--yes"], {"GOOGLE_CLOUD_PROJECT": "p"}, make_client=lambda: client) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == len(mg.CASES) + 1 and len(calls) == len(mg.CASES)
    assert all(json.loads(x) for x in out) and "summary" in json.loads(out[-1])


def test_measurement_prompts_are_synthetic_and_short():
    for name, build, _ in mg.CASES:
        req = build()
        assert len(req.contents) < 200 and "http" not in req.contents, name
