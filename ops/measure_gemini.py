"""Vertex AI の実測（手動・最大8回・短い出力）。thinking の設定名と usage_metadata の thoughts の扱いを調べる。

使い方（人間が実行する。コスト目安は数円以下）:
    GOOGLE_CLOUD_PROJECT=<id> python -m ops.measure_gemini --yes
環境変数: GEMINI_LOCATION（既定 global）/ GEMINI_MODEL（既定 gemini-3.7-flash）。

結果の JSON（1ケース1行＋結論）を、app/model/gemini.py の docstring「実測の状態」へ書き戻す。
GOOGLE_CLOUD_PROJECT が無い時は何も呼ばずに「未実測」と出して終了する（プロジェクト ID を探しに行かない）。
プロンプトは合成した短い文だけで、第三者の文章を使わない。
"""
import asyncio
import json
import sys
from collections.abc import Callable, Mapping
from typing import Any

from app.config import DEFAULT_GEMINI_LOCATION, DEFAULT_GEMINI_MODEL, load_settings
from app.contracts import (
    ModelPurpose,
    ModelRequest,
    ReaderOutput,
    ToolDecl,
    ToolName,
)
from app.errors import AppError, classify
from app.model.gemini import GeminiPort, ThinkingParam
from app.model.port import ModelPort

MAX_CALLS = 8
TIMEOUT_S = 25.0

_SYSTEM = "あなたは短く答えるアシスタントです。"
_ARITH = "17掛ける23の答えを、数字だけで返してください。"
_SPEC = "架空の要項: 公開説明文は800字以内とする。提出物のURLは審査員が開けること。デモ動画は任意である。"


def _reader(thinking_budget: int | None, *, schema: bool = False, max_out: int = 256) -> ModelRequest:
    return ModelRequest(
        purpose=ModelPurpose.READER,
        system=_SYSTEM,
        contents=_SPEC if schema else _ARITH,
        response_model=ReaderOutput if schema else None,
        max_output_tokens=max_out,
        thinking_budget=thinking_budget,
        timeout_s=TIMEOUT_S,
    )


def _planner() -> ModelRequest:
    decl = ToolDecl.for_tool(ToolName.FINISH, "検査を終了する")
    return ModelRequest(
        purpose=ModelPurpose.PLANNER,
        system=_SYSTEM,
        contents='{"turn":1,"requirements":[],"allowed_tools":["finish"]}',
        tools=(decl,),
        allowed_tool_names=(ToolName.FINISH,),
        max_output_tokens=128,
        thinking_budget=512,
        timeout_s=TIMEOUT_S,
    )


# (名前, 要求, thinking の設定名)。8ケース＝上限ちょうど。
CASES: list[tuple[str, Callable[[], ModelRequest], ThinkingParam]] = [
    ("plain_default_thinking", lambda: _reader(None), "thinking_budget"),
    ("thinking_budget_512", lambda: _reader(512), "thinking_budget"),
    ("thinking_budget_0", lambda: _reader(0), "thinking_budget"),
    ("thinking_level_low", lambda: _reader(512), "thinking_level"),
    ("thinking_level_high", lambda: _reader(4096), "thinking_level"),
    ("reader_schema_budget_1024", lambda: _reader(1024, schema=True, max_out=512), "thinking_budget"),
    ("planner_function_call_any", _planner, "thinking_budget"),
    ("reader_schema_budget_512", lambda: _reader(512, schema=True, max_out=512), "thinking_budget"),
]
assert len(CASES) <= MAX_CALLS


def interpret_usage(u: Mapping[str, Any]) -> str:
    """usage_metadata の生の値から、thoughts が candidates に含まれるかを推定する（合計の足し算で判定）。"""
    p, c, t, total = (u.get(k) or 0 for k in ("prompt_token_count", "candidates_token_count", "thoughts_token_count", "total_token_count"))
    if not t:
        return "thoughts=0（この呼び出しでは判定不能）"
    if total == p + c + t:
        return "thoughts は candidates とは別（total = prompt + candidates + thoughts）→ tokens_out は足す"
    if total == p + c:
        return "total が thoughts を足していない（candidates に含まれる可能性）→ tokens_out の二重計上に注意"
    return f"判定不能（prompt={p} candidates={c} thoughts={t} total={total}）"


class _UsageSpy:
    """client を包み、最後の応答の usage_metadata の生の値を控える（GeminiPort は total を落とすため）。"""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.last_usage: dict[str, Any] = {}
        spy = self

        class _Models:
            async def generate_content(self, **kw: Any) -> Any:
                resp = await client.aio.models.generate_content(**kw)
                meta = getattr(resp, "usage_metadata", None)
                spy.last_usage = meta.model_dump(exclude_none=True, mode="json") if meta is not None else {}
                return resp

        class _Aio:
            models = _Models()

        self.aio = _Aio()


async def run_measurements(
    make_client: Callable[[], Any], *, model_id: str, project: str | None, location: str, max_calls: int = MAX_CALLS
) -> list[dict[str, Any]]:
    """ケースを順に1回ずつ呼ぶ。失敗しても次へ進み、エラーは ErrorCode と HTTP コードだけ記録する。"""
    spy = _UsageSpy(make_client())
    results: list[dict[str, Any]] = []
    for name, build, thinking_param in CASES[:max_calls]:
        port: ModelPort = GeminiPort(
            model_id=model_id, project=project, location=location, client=spy, thinking_param=thinking_param
        )
        spy.last_usage = {}
        row: dict[str, Any] = {"case": name, "thinking_param": thinking_param}
        try:
            resp = await port.generate(build())
            row.update(
                ok=True,
                finish_reason=resp.finish_reason,
                text_chars=len(resp.text or ""),
                function_calls=[c.name for c in resp.function_calls],
                usage_raw=spy.last_usage,
                tokens_in=resp.usage.tokens_in,
                tokens_out_by_our_definition=resp.usage.tokens_out,
                usage_reading=interpret_usage(spy.last_usage),
                latency_ms=resp.latency_ms,
            )
        except AppError as e:
            cause = e.__cause__
            row.update(ok=False, error_code=e.code.value, http_status=getattr(cause, "code", None))
        except Exception as e:  # 想定外でも続行して記録する
            row.update(ok=False, error_code=classify(e).value, http_status=getattr(e, "code", None))
        results.append(row)
    return results


def main(argv: list[str], environ: Mapping[str, str], make_client: Callable[[], Any] | None = None) -> int:
    settings = load_settings(environ)
    if "--yes" not in argv:
        print(f"Vertex AI を最大 {len(CASES)} 回呼びます。実行するなら --yes を付けてください。", file=sys.stderr)
        return 2
    if not settings.google_cloud_project:
        print("未実測: GOOGLE_CLOUD_PROJECT が未設定のため何も呼んでいません。", file=sys.stderr)
        return 2

    def default_client() -> Any:
        from google import genai

        return genai.Client(vertexai=True, project=settings.google_cloud_project, location=settings.gemini_location)

    model_id = environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    rows = asyncio.run(
        run_measurements(
            make_client or default_client,
            model_id=model_id,
            project=settings.google_cloud_project,
            location=settings.gemini_location or DEFAULT_GEMINI_LOCATION,
        )
    )
    for row in rows:
        print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    ok = [r for r in rows if r["ok"]]
    print(json.dumps({"summary": {"calls": len(rows), "ok": len(ok), "model": model_id}}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import os

    raise SystemExit(main(sys.argv[1:], os.environ))
