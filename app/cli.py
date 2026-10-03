"""ローカル CLI: `python -m app.cli <preset> [--inspect-mode planner|router] [--format json|html] [--out PATH] [--trace PATH]`。

プリセット ID（config.PRESET_IDS）だけを受ける（任意の URL は受けない＝閉世界）。取得は SafeFetch（プロセス内）、モデルは
Vertex の Gemini（GOOGLE_CLOUD_PROJECT が要る。ADC で認証。API キーは使わない）。ライブ実行を伴うので、手元で試す時の入口で、
テストは `main(..., fetch=, reader_model=, planner_model=)` へフェイクを渡して通す（実ネットワーク・Vertex を使わない）。

終了コード: 0=DONE／DEGRADED（部分結果も出力する）、2=ABORTED、1=実行できなかった（設定の誤りなど。公開してよい固定文だけを出す）。
"""
import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from app.agent.planner import InspectMode
from app.agent.report import report_html, report_json
from app.agent.run import run_audit
from app.agent.trace import write_jsonl
from app.config import PRESET_IDS, RUN_CAPS, Settings, build_presets, load_settings
from app.contracts import FetchPort, RunStatus
from app.errors import AppError, ErrorCode, PublicError, classify
from app.jsonlog import log_exception
from app.model.port import ModelPort


def _build_fetch(preset_prefixes) -> FetchPort:  # noqa: ANN001
    from app.net.safefetch import SafeFetch

    return SafeFetch(preset_prefixes)


def _build_model(settings: Settings, model_id: str) -> ModelPort:
    from app.model.gemini import GeminiPort
    from app.model.retry import RetryingPort

    port = GeminiPort.from_settings(settings, model_id=model_id)
    return RetryingPort(port, retries=RUN_CAPS.model_retries, backoff_s=RUN_CAPS.retry_backoff_s)


def main(
    argv: Sequence[str] | None = None,
    *,
    fetch: FetchPort | None = None,
    reader_model: ModelPort | None = None,
    planner_model: ModelPort | None = None,
    settings: Settings | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out, err = stdout or sys.stdout, stderr or sys.stderr
    ap = argparse.ArgumentParser(prog="python -m app.cli", description="要項監査エージェント（読み取り専用）をプリセットで実行する")
    ap.add_argument("preset", choices=PRESET_IDS)
    ap.add_argument("--inspect-mode", choices=[m.value for m in InspectMode], default=InspectMode.PLANNER.value)
    ap.add_argument("--format", choices=["json", "html"], default="json")
    ap.add_argument("--out", type=Path, help="結果の出力先（省略時は標準出力）")
    ap.add_argument("--trace", type=Path, help="トレースの JSONL の出力先")
    args = ap.parse_args(argv)

    settings = settings or load_settings()
    preset = build_presets(settings)[args.preset]
    mode = InspectMode(args.inspect_mode)
    try:
        fetch = fetch or _build_fetch(preset.allowed_prefixes)
        reader = reader_model or _build_model(settings, settings.gemini_model_reader)
        planner = planner_model or (_build_model(settings, settings.gemini_model_planner) if mode is InspectMode.PLANNER else None)
        res = asyncio.run(
            run_audit(preset, fetch=fetch, reader_model=reader, planner_model=planner, inspect_mode=mode, settings=settings)
        )
    except Exception as e:  # noqa: BLE001  公開してよいのは ErrorCode と固定文だけ。詳細は非公開ログへ
        log_exception("cli.run_failed", e)
        pe = PublicError.from_code(classify(e) if isinstance(e, AppError) else ErrorCode.INTERNAL)
        print(f"{pe.code.value}: {pe.message}", file=err)
        return 1

    text = report_json(res.record) if args.format == "json" else report_html(res.record)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        out.write(text if text.endswith("\n") else text + "\n")
    if args.trace:
        write_jsonl(args.trace, res.events)
    return 2 if res.record.status is RunStatus.ABORTED else 0


if __name__ == "__main__":
    raise SystemExit(main())
