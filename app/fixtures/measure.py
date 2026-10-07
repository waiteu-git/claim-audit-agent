"""測定の道具: 欠陥の変種 × {Planner, router} の表（ツール呼び出し数・誤った「absent」・確認不能・トークン・推定費用）。

  python -m app.fixtures.eval                 # オフライン（既定）。Reader は OracleReader、Planner は RulePlanner（規則）。モデルは呼ばない
  python -m app.fixtures.eval --live          # 実モデル（Vertex）で測る。認証は ADC。GOOGLE_CLOUD_PROJECT が要る

出力は Markdown の表と JSON（標準出力）。結果は測ったとおりに出す（良く見せる処理は入れない）:
  * オフラインの行は、モデルを呼ばない。トークンと費用は「台本のモデルが数えた見積もり」で、実測ではない（tokens_source=estimated）。
    RulePlanner は「案内ページを辿る Planner」を規則で再現したもので、実際の Planner（Gemini）の結果ではない。
  * --live の行は、実モデルの usage から数えた値（tokens_source=measured）。費用は料金表（config.PRICE_TABLE。確認日と出典はそこ）による推定。
  * --live は呼び出し回数の上限をコードで持つ（既定 MAX_LIVE_CALLS_DEFAULT・上限 MAX_LIVE_CALLS_HARD）。再試行も1回と数える。
    上限に達した後の行は実行せず「skipped」と出す（途中で達した行は capped と出す）。
  * 行の順序は、案内ページの変種（g1found・g2missing）→ 既存の6変種。上限が小さい時に、差が出る変種から測れるようにするため。
"""
import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.config import RUN_CAPS, Settings
from app.contracts import ModelRequest, ModelResponse, RunRecord, TraceType
from app.errors import AppError, ErrorCode
from app.fixtures import gen
from app.fixtures.eval import EVAL_HOST, OracleReader, RulePlanner, score, variant_preset
from app.fixtures.site import FixtureFetch, FixtureSite
from app.model.port import ModelPort

MAX_LIVE_CALLS_DEFAULT = 40
MAX_LIVE_CALLS_HARD = 120
MODES = (InspectMode.PLANNER, InspectMode.ROUTER)
COLUMNS = (
    ("variant", "変種"),
    ("mode", "検査"),
    ("model", "モデル"),
    ("status", "状態"),
    ("tool_calls", "ツール呼び出し"),
    ("model_calls", "モデル呼び出し"),
    ("detected", "検出"),
    ("false_absent", "誤った absent"),
    ("unverifiable", "確認不能"),
    ("tokens", "トークン（入/出）"),
    ("cost_jpy", "推定費用（円）"),
)


def all_variants() -> tuple[gen.Variant, ...]:
    """測る変種の順序: 案内ページの変種 → 既存の6変種。"""
    return (*gen.GUIDE_VARIANTS, *gen.VARIANTS)


# ---- 呼び出し回数の上限（--live）------------------------------------------------------------------------
class CallBudget:
    def __init__(self, limit: int) -> None:
        if not 1 <= limit <= MAX_LIVE_CALLS_HARD:
            raise ValueError(f"呼び出しの上限は 1〜{MAX_LIVE_CALLS_HARD} 回")
        self.limit = limit
        self.used = 0

    @property
    def left(self) -> int:
        return self.limit - self.used

    def take(self) -> None:
        if self.used >= self.limit:
            raise AppError(ErrorCode.QUOTA, "測定の呼び出し上限に達しました")
        self.used += 1


class CappedPort:
    """ModelPort を包み、呼ぶ前に1回ずつ数える。上限に達していたら呼ばずに QUOTA（再試行しない）を投げる。
    再試行（RetryingPort）はこれの外側に置く＝再試行の1回ずつも数える。"""

    def __init__(self, inner: ModelPort, budget: CallBudget) -> None:
        self._inner = inner
        self._budget = budget

    @property
    def model_id(self) -> str:
        return self._inner.model_id

    async def generate(self, request: ModelRequest) -> ModelResponse:
        self._budget.take()
        return await self._inner.generate(request)


@dataclass(frozen=True)
class ModelSet:
    reader: ModelPort
    planner: ModelPort | None
    label: str
    tokens_source: str  # "estimated"（オフラインの台本）／"measured"（実モデルの usage）


def offline_models(mode: InspectMode) -> ModelSet:
    if mode is InspectMode.PLANNER:
        return ModelSet(OracleReader(), RulePlanner(), "oracle-reader / rule-planner", "estimated")
    return ModelSet(OracleReader(), None, "oracle-reader / router", "estimated")


# ---- 1行を測る -------------------------------------------------------------------------------------------
def summarize(v: gen.Variant, mode: InspectMode, record: RunRecord, row: dict[str, Any], models: ModelSet) -> dict[str, Any]:
    b = record.budget
    caps = RUN_CAPS
    tokens_in, tokens_out = caps.tokens_in - b.tokens_in_left, caps.tokens_out - b.tokens_out_left
    return {
        "variant": v.name,
        "mode": mode.value,
        "model": models.label,
        "status": record.status.value,
        "skipped": False,
        "capped": False,
        "tool_calls": caps.tool_calls - b.tool_calls_left,
        "model_calls": caps.model_calls_total - b.model_calls_left,
        "detected": f"{len(row['detected'])}/{row['expected']}",
        "false_positives": row["false_positives"],
        "false_absent": row["false_absent"],
        "unverifiable": row["unverifiable"],
        "replans": sum(1 for e in record.events if e.type is TraceType.REPLAN),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "tokens_source": models.tokens_source,
        "est_cost_jpy": round(record.summary.est_cost_micro_jpy / 1e6, 4),
    }


def skipped_row(v: gen.Variant, mode: InspectMode, label: str, why: str) -> dict[str, Any]:
    return {"variant": v.name, "mode": mode.value, "model": label, "status": "skipped", "skipped": True, "reason": why}


async def measure_row(v: gen.Variant, mode: InspectMode, models: ModelSet) -> dict[str, Any]:
    preset = variant_preset(v)
    fetch = FixtureFetch(FixtureSite(gen.build_site(v)), EVAL_HOST, preset.allowed_prefixes)
    res = await run_audit(
        preset, fetch=fetch, reader_model=models.reader, planner_model=models.planner, inspect_mode=mode, settings=Settings()
    )
    row = score(res.record, gen.expected_for(v))
    return summarize(v, mode, res.record, row, models)


async def measure_offline(variants: Sequence[gen.Variant] | None = None) -> dict[str, Any]:
    rows = [await measure_row(v, m, offline_models(m)) for v in (variants or all_variants()) for m in MODES]
    return {"live": False, "rows": rows, "totals": totals(rows)}


async def measure_live(
    settings: Settings, *, max_calls: int = MAX_LIVE_CALLS_DEFAULT, only: Sequence[str] | None = None
) -> dict[str, Any]:
    """実モデルで測る。呼び出し回数の上限を超える前に止まる。モデルの失敗は行の状態（DEGRADED 等）にそのまま出る。"""
    from app.model.gemini import GeminiPort
    from app.model.retry import RetryingPort

    budget = CallBudget(max_calls)  # 上限の指定が不正なら、何も呼ぶ前に断る
    if not settings.google_cloud_project:
        raise AppError(ErrorCode.FATAL_CONFIG, "GOOGLE_CLOUD_PROJECT が未設定です（--live は実モデルを呼びます）")

    def port(model_id: str) -> RetryingPort:
        inner = CappedPort(GeminiPort.from_settings(settings, model_id=model_id), budget)
        return RetryingPort(inner, retries=RUN_CAPS.model_retries, backoff_s=RUN_CAPS.retry_backoff_s)

    reader, planner = port(settings.gemini_model_reader), port(settings.gemini_model_planner)
    variants = [v for v in all_variants() if only is None or v.name in only]
    rows: list[dict[str, Any]] = []
    for v in variants:
        for m in MODES:
            label = f"{reader.model_id} / {planner.model_id if m is InspectMode.PLANNER else 'router'}"
            if budget.left <= 0:
                rows.append(skipped_row(v, m, label, "呼び出し上限に達したため実行していません"))
                continue
            models = ModelSet(reader, planner if m is InspectMode.PLANNER else None, label, "measured")
            row = await measure_row(v, m, models)
            row["capped"] = budget.left <= 0
            rows.append(row)
    return {"live": True, "calls_used": budget.used, "calls_limit": budget.limit, "rows": rows, "totals": totals(rows)}


def totals(rows: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for m in MODES:
        done = [r for r in rows if r["mode"] == m.value and not r.get("skipped")]
        out[m.value] = {
            "rows": len(done),
            "tool_calls": sum(r["tool_calls"] for r in done),
            "model_calls": sum(r["model_calls"] for r in done),
            "false_absent": sum(r["false_absent"] for r in done),
            "unverifiable": sum(r["unverifiable"] for r in done),
            "tokens_in": sum(r["tokens_in"] for r in done),
            "tokens_out": sum(r["tokens_out"] for r in done),
            "est_cost_jpy": round(sum(r["est_cost_jpy"] for r in done), 4),
        }
    return out


# ---- 出力 ------------------------------------------------------------------------------------------------
def _cell(r: dict[str, Any], key: str) -> str:
    if r.get("skipped"):
        return {"variant": r["variant"], "mode": r["mode"], "model": r["model"], "status": "skipped"}.get(key, "—")
    if key == "tokens":
        return f"{r['tokens_in']:,}/{r['tokens_out']:,}" + ("*" if r["tokens_source"] == "estimated" else "")
    if key == "cost_jpy":
        return f"{r['est_cost_jpy']:.4f}" + ("*" if r["tokens_source"] == "estimated" else "")
    if key == "status" and r.get("capped"):
        return f"{r['status']}（上限）"
    return str(r[key])


def to_markdown(table: dict[str, Any]) -> str:
    head = "| " + " | ".join(h for _, h in COLUMNS) + " |"
    sep = "|" + "|".join("---" for _ in COLUMNS) + "|"
    lines = [head, sep] + ["| " + " | ".join(_cell(r, k) for k, _ in COLUMNS) + " |" for r in table["rows"]]
    t = table["totals"]
    lines.append("")
    for m in MODES:
        x = t[m.value]
        lines.append(
            f"- {m.value}: {x['rows']} 行・ツール {x['tool_calls']}・モデル {x['model_calls']}・誤った absent {x['false_absent']}・"
            f"確認不能 {x['unverifiable']}・トークン {x['tokens_in']:,}/{x['tokens_out']:,}・推定 {x['est_cost_jpy']:.4f} 円"
        )
    if table["live"]:
        lines.append(f"- 実モデルの呼び出し: {table['calls_used']} / 上限 {table['calls_limit']} 回。費用は料金表（config.PRICE_TABLE）による推定")
    else:
        lines.append(
            "- オフライン: モデルを呼んでいません。* は台本のモデルが数えた見積もりで、実測ではありません。"
            "Planner は規則で動く RulePlanner（案内ページを辿る）で、実際のモデルの結果ではありません。実モデルは --live"
        )
    return "\n".join(lines)


def to_json(table: dict[str, Any]) -> str:
    return json.dumps(table, ensure_ascii=False, indent=1, sort_keys=True)


def run(argv_live: bool, *, max_calls: int, only: Sequence[str] | None) -> dict[str, Any]:
    if argv_live:
        from app.config import load_settings

        return asyncio.run(measure_live(load_settings(), max_calls=max_calls, only=only))
    variants = [v for v in all_variants() if only is None or v.name in only]
    return asyncio.run(measure_offline(variants))
