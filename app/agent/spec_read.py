"""要項モード（第11弾）: 利用者が入れた公開ページを取り、Reader だけにかけて、要件の一覧（種別・根拠の一文・出典）だけを返す。

  read_spec_pages(refs, fetch=..., reader_model=...) -> SpecReadOutcome   結果（SpecOnlyRecord）か、結果にならない失敗の ErrorCode

複数リンク（最大3件）: 入力の URL を1つずつ1ページだけ取り、取れたページを出典 D1・D2・D3 の文書として Reader に渡す（LP＋FAQ の
複数文書と同じ扱い）。取れない・形式が違う（PDF など）ページは、そのページだけを飛ばし、結果の skipped_pages に「何番目か・理由の種類」
を載せる（URL は載せない）。全部取れなければ固定文のエラー。費用は1実行の既存の上限（モデル呼び出し数・トークン）のまま
（超えたら打ち切って部分結果＝DEGRADED）。

流れ: ACQUIRE（入力の URL を1つずつ FetchPort で取る。リンクは辿らない）→ 既存の洗浄（ingest.sanitize。隠しテキストの分離）→
READ（既存の reader.read_spec。注入の疑いの区間は mask_injections で伏せ、引用は原文と照合し、受け付けなかった引用は1回だけ
引用し直させる）→ REPORT（引用の最終再検証だけ）。

ここに無いもの（呼ばない・import しない。tests/test_spec_mode.py が AST と実行の両方で固定する）:
  Planner・router・AUTORUN・ツール（fetch_link・http_probe・run_check）・判定表（adjudicate）・矛盾の判定。
  Reader がリンクに役割（docs など）を付けても、次の取得はしない（取得するのは入力の URL だけで、取得の手を持つ部品がここに無い）。
  リンク表の行も、すべて取得スコープの外（scope=()）として作る。

ページの文面は、検証済みの引用（VerifiedSpan）以外は結果に持ち込まない。注入の疑いの検知は件数と位置だけを残し、抜粋（snippet）は
空にする（入力の URL・偽の命令の文を結果とトレースに運ばない）。ログに出すのは URL の sha256 の先頭12桁と件数だけ。
"""
import asyncio
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from app.agent.budget import BudgetMeter, Clock
from app.agent.governor import Governor
from app.agent.reader import read_spec
from app.agent.state import RunState
from app.agent.trace import TraceLog
from app.config import RUN_CAPS, Settings
from app.contracts import (
    SPEC_URL_PRESET_ID,
    AbortReason,
    Actor,
    ContentKind,
    DocRole,
    FetchKind,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    FetchResult,
    Phase,
    Preset,
    PresetKind,
    RunCaps,
    RunMode,
    RunStatus,
    RunSummary,
    SPEC_MAX_URLS,
    SanitizedDoc,
    SpecOnlyRecord,
    SpecSkippedPage,
    SpecSkipReason,
    TraceEvent,
    TraceType,
)
from app.errors import ErrorCode, classify
from app.ingest.sanitize import sanitize
from app.jsonlog import log_event
from app.model.port import ModelPort
from app.spec_url import SpecRef, spec_log_id

SPEC_PRESET = Preset(
    preset_id=SPEC_URL_PRESET_ID,
    label_ja="要項のURLから要件の一覧だけを作る",
    kind=PresetKind.SPEC_URL,
    spec_seed_urls=(),  # 取得先はプリセットに固定しない（入力の URL。取得の可否は S3 の規則が決める）
    allowed_prefixes=(),  # リンク表はすべてスコープの外＝辿れない
)


@dataclass(frozen=True)
class SpecReadOutcome:
    record: SpecOnlyRecord | None = None
    error: ErrorCode | None = None  # record が無い時の理由（固定文は errors.PUBLIC_MESSAGES）
    cost_micro_jpy: int = 0  # モデル呼び出しの見積もり費用（精算に使う）


def skip_reason(result: FetchResult | None) -> SpecSkipReason | None:
    """読めるページなら None、読めないなら理由の種類。S3 の規則を信用しすぎず、こちらでも確かめる:
    転送を経ていない 200・html か plain・打切りでない・空でない・NUL を含まない。"""
    if result is None:
        return SpecSkipReason.FETCH_FAILED
    o = result.outcome
    if o is FetchOutcome.BLOCKED:
        return SpecSkipReason.REFUSED  # S3 が規則を持たない（SPEC_FETCH_ENABLED なし）・規則の外・私的アドレス
    if o is FetchOutcome.UNSUPPORTED_TYPE:
        return SpecSkipReason.UNSUPPORTED
    if o is FetchOutcome.TOO_LARGE or result.truncated:
        return SpecSkipReason.TOO_LARGE
    if o is not FetchOutcome.OK or result.status != 200 or result.redirects:
        return SpecSkipReason.FETCH_FAILED  # 404・3xx（転送は追わない）・5xx・通信の失敗・期限切れ
    if result.content_kind not in (ContentKind.HTML, ContentKind.PLAIN) or b"\x00" in result.body:
        return SpecSkipReason.UNSUPPORTED
    if not result.body:
        return SpecSkipReason.EMPTY
    return None


def _failure_code(skipped: list[SpecSkippedPage]) -> ErrorCode:
    if skipped and all(s.reason is SpecSkipReason.REFUSED for s in skipped):
        return ErrorCode.SPEC_UNAVAILABLE  # 全部を S3 が拒否した＝いま使えない
    return ErrorCode.FETCH_FAILED


def _without_snippets(doc: SanitizedDoc) -> SanitizedDoc:
    """注入の疑いの検知から抜粋を外す（件数と位置は残す）。偽の命令の文を結果・トレースに運ばない。"""
    if not doc.injection_signals:
        return doc
    sigs = tuple(s.model_copy(update={"snippet": ""}) for s in doc.injection_signals)
    return doc.model_copy(update={"injection_signals": sigs})


async def read_spec_pages(
    refs: Sequence[SpecRef],
    *,
    fetch: FetchPort,
    reader_model: ModelPort,
    settings: Settings | None = None,
    caps: RunCaps = RUN_CAPS,
    clock: Clock = time.monotonic,
    trace_sink: Callable[[TraceEvent], None] | None = None,
) -> SpecReadOutcome:
    settings = settings or Settings()
    meter = BudgetMeter(caps, clock)
    trace = TraceLog(secrets.token_urlsafe(16), meter.elapsed_ms, sink=trace_sink)
    state = RunState(preset=SPEC_PRESET)
    gov = Governor(state, meter, trace, kill_switch=lambda: settings.kill_switch)
    started = datetime.now(UTC)

    if not 1 <= len(refs) <= SPEC_MAX_URLS:
        raise ValueError("要項モードの URL は1〜3件")
    gov.enter(Phase.ACQUIRE)
    skipped: list[SpecSkippedPage] = []
    for i, ref in enumerate(refs, start=1):
        if gov.check_stop():
            break
        if not meter.budget.can_fetch(kind=FetchKind.ACQUIRE):
            break
        result: FetchResult | None = None
        code = "fetched"
        try:
            result = await fetch.fetch(FetchRequest(url=ref.url))
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001  取得層の想定外。分類した ErrorCode だけを残す（例外の中身は出さない）
            code = classify(e).value.lower()
        finally:
            meter.budget.charge_fetch(None, FetchKind.ACQUIRE)
        if result is not None:
            code = result.outcome.value
        trace.emit(gov.phase, Actor.TOOL, TraceType.TOOL_RESULT, name="acquire", reason_code=code,
                   bytes=len(result.body) if result is not None else None)  # fmt: skip
        why = skip_reason(result)
        doc: SanitizedDoc | None = None
        if why is None:
            try:
                doc = sanitize(result, doc_id=state.next_doc_id(), role=DocRole.SPEC, label=f"要項 {i}", scope=())  # type: ignore[arg-type]
            except ValueError:
                why = SpecSkipReason.UNSUPPORTED
        if doc is None or why is not None:
            skipped.append(SpecSkippedPage(page=i, reason=why or SpecSkipReason.FETCH_FAILED))
            log_event("spec.page_skipped", spec=spec_log_id(ref), page=i, code=code, reason=(why or SpecSkipReason.FETCH_FAILED).name,
                      status=result.status if result is not None else None)  # fmt: skip
            continue
        state.add_doc(_without_snippets(doc))

    if gov.status is RunStatus.ABORTED:
        return SpecReadOutcome(error=ErrorCode.KILLED if gov.aborted_reason is AbortReason.KILL else ErrorCode.CANCELLED)
    if not state.docs:
        return SpecReadOutcome(error=_failure_code(skipped))

    gov.enter(Phase.READ)
    read = await read_spec(state, gov, reader_model)
    gov.check_stop()
    gov.enter(Phase.REPORT)
    reverified = read.checker.reverify(state.requirements)  # 最終再検証（原文に当たらなくなった引用は推測へ落ちる）。判定ではない
    reqs = reverified.requirements
    gov.snapshot()
    if gov.status is not RunStatus.ABORTED:
        gov.enter(Phase.DONE)
    injection = tuple(s for d in state.docs.values() for s in d.injection_signals)
    summary = RunSummary.compute(reqs, (), (), injection, trace.events, capped=state.capped)
    record = SpecOnlyRecord(
        run_id=trace.run_id,
        env=settings.env,
        mode=RunMode.LIVE,
        status=gov.status,
        degraded_reason=gov.degraded_reason if gov.status is RunStatus.DEGRADED else None,
        aborted_reason=gov.aborted_reason,
        prompt_version=settings.prompt_version,
        reader_model=reader_model.model_id,
        planner_model="none",
        started_at=started,
        docs=state.doc_metas(),
        requirements=reqs,
        injection_signals=injection,
        summary=summary,
        budget=meter.budget.snapshot(),
        events=tuple(trace.events),
        omitted_events=trace.omitted,
        skipped_pages=tuple(skipped),
    )
    log_event("spec.read_done", pages=len(state.docs), skipped=len(skipped), requirements=len(reqs), status=gov.status.value)
    return SpecReadOutcome(record=record, cost_micro_jpy=summary.est_cost_micro_jpy)
