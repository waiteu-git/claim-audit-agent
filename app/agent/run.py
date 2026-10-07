"""1実行のオーケストレーション: ACQUIRE → READ → AUTORUN → INSPECT → ADJUDICATE → REPORT（設計 §3 の縦1本。PERSIST は G3 以降）。

  ACQUIRE    プリセットの URL を FetchPort で取得・洗浄（acquire.py）
  READ       Reader が要件を抜き、QuoteChecker が引用を検証（reader.py）
  AUTORUN    前提がコード判定で揃う検査を必ず走らせる。モデル無し・Planner／router の両モードで同じ（autorun_phase.py）
  INSPECT    Planner または router が、AUTORUN で決まらなかった要件を、同じ Governor・同じツールで検査（planner.py・tools.py）
  ADJUDICATE 判定表（adjudicate.py）。モデルの出力は観測・印の形でしか入らず、判定を書けるのはここだけ
  REPORT     引用の最終再検証 → RunRecord

上限到達（予算・モデル失敗・拒否の連続）は DEGRADED、キルスイッチ・壁時計は ABORTED。例外にせず、理由つきの結果にする
（設定エラー FATAL_CONFIG だけは呼び出し側へ伝える＝実行を始められない）。DEGRADED では INSPECT を打ち切り、検査していない
要件は理由コードつきの確認不能（BUDGET・TRANSIENT）で必ず出す。
"""
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.adjudicate import adjudicate, find_contradictions
from app.agent.acquire import acquire
from app.agent.autorun_phase import run_autorun_phase
from app.agent.budget import BudgetMeter, Clock
from app.agent.governor import Governor
from app.agent.planner import InspectMode, run_planner, run_router
from app.agent.reader import read_spec
from app.agent.state import RunState
from app.agent.tools import ToolRegistry
from app.agent.trace import TraceLog
from app.config import RUN_CAPS, Settings
from app.contracts import (
    Actor,
    AdjudicationInput,
    DegradedReason,
    FetchPort,
    Kind,
    PageClass,
    Phase,
    Preset,
    ReqState,
    RunCaps,
    RunMode,
    RunRecord,
    RunStatus,
    RunSummary,
    TraceEvent,
    TraceType,
    UnverifiableMark,
    UnverifiableReason,
    Verdict,
    VerifiedRequirement,
)
from app.model.port import ModelPort
from app.quotes import DocIndex, QuoteChecker, ReverifyIssue

_DEGRADED_MARK = {
    DegradedReason.BUDGET: UnverifiableReason.BUDGET,
    DegradedReason.MODEL_FAILURE: UnverifiableReason.TRANSIENT,
}  # DENIAL_STREAK には対応する理由が無い（判定表の既定＝根拠なし・範囲外に任せる）


@dataclass
class RunResult:
    record: RunRecord
    state: RunState
    governor: Governor
    trace: TraceLog
    reverify_issues: tuple[ReverifyIssue, ...] = ()
    events: tuple[TraceEvent, ...] = field(default=())


def record_degraded_reason(status: RunStatus, reason: DegradedReason | None) -> DegradedReason | None:
    """実行記録に載せる劣化理由。Governor は DEGRADED の後に ABORTED になっても最初の理由を残す（トレース用）が、
    RunRecord は DEGRADED の時だけ理由を許す。10/7 のライブ実行で、劣化→壁時計切れの順に起きて記録が作れず結果が消えた。"""
    return reason if status is RunStatus.DEGRADED else None


async def run_audit(
    preset: Preset,
    *,
    fetch: FetchPort,
    reader_model: ModelPort,
    planner_model: ModelPort | None = None,
    inspect_mode: InspectMode = InspectMode.PLANNER,
    settings: Settings | None = None,
    caps: RunCaps = RUN_CAPS,
    run_id: str | None = None,
    clock: Clock = time.monotonic,
    sleep: "Callable[[float], Awaitable[None]] | None" = None,
    started_at: datetime | None = None,
    trace_sink: Callable[[TraceEvent], None] | None = None,
    planner_skip_when_idle: bool = True,
) -> RunResult:
    if inspect_mode is InspectMode.PLANNER and planner_model is None:
        raise ValueError("inspect_mode=planner には planner_model が要ります")
    settings = settings or Settings()
    meter = BudgetMeter(caps, clock)
    trace = TraceLog(run_id or secrets.token_urlsafe(16), meter.elapsed_ms, sink=trace_sink)
    state = RunState(preset=preset)
    gov = Governor(state, meter, trace, kill_switch=lambda: settings.kill_switch)
    started = started_at or datetime.now(UTC)
    registry_kwargs = {} if sleep is None else {"sleep": sleep}
    registry = ToolRegistry(state=state, governor=gov, fetch=fetch, **registry_kwargs)

    def result(record_reqs: tuple[VerifiedRequirement, ...], verdicts: tuple[Verdict, ...], issues=(), *, snapshot: bool = True,
               contradictions: tuple = ()) -> RunResult:  # noqa: ANN001
        if snapshot:  # 中止の時は、ここで最後の予算の要約を残す（通常は DONE の前に残す）
            gov.snapshot()
        injection = tuple(s for d in state.docs.values() for s in d.injection_signals)
        record = RunRecord(
            run_id=trace.run_id,
            env=settings.env,
            mode=RunMode.LIVE,
            status=gov.status,
            degraded_reason=record_degraded_reason(gov.status, gov.degraded_reason),
            aborted_reason=gov.aborted_reason,
            preset_id=preset.preset_id,
            prompt_version=settings.prompt_version,
            reader_model=reader_model.model_id,
            planner_model=planner_model.model_id if planner_model is not None else InspectMode.ROUTER.value,
            started_at=started,
            docs=state.doc_metas(),
            requirements=record_reqs,
            verdicts=verdicts,
            contradictions=contradictions,
            injection_signals=injection,
            observations=tuple(state.observations)[:64],
            summary=RunSummary.compute(record_reqs, verdicts, contradictions, injection, trace.events, capped=state.capped),
            budget=meter.budget.snapshot(),
            events=tuple(trace.events),
            omitted_events=trace.omitted,
        )
        return RunResult(record, state, gov, trace, tuple(issues), tuple(trace.events))

    gov.enter(Phase.ACQUIRE)
    await acquire(state, gov, fetch)
    if gov.check_stop() and gov.status is RunStatus.ABORTED:
        return result(tuple(state.requirements), ())

    gov.enter(Phase.READ)
    checker: QuoteChecker | None = None
    proposals: dict[str, PageClass] = {}
    if not gov.stopped:
        read = await read_spec(state, gov, reader_model)
        checker = read.checker
        proposals = read.page_class_proposals
    if checker is None:
        checker = QuoteChecker(DocIndex(()))
    if gov.check_stop() and gov.status is RunStatus.ABORTED:
        return result(tuple(state.requirements), ())

    gov.enter(Phase.AUTORUN)
    if not gov.stopped and state.requirements:
        await run_autorun_phase(state, gov, registry, fetch, page_class_proposals=proposals)
    if gov.status is RunStatus.ABORTED:
        return result(tuple(state.requirements), ())

    gov.enter(Phase.INSPECT)
    if not gov.stopped and state.requirements:
        if inspect_mode is InspectMode.ROUTER:
            await run_router(state, gov, registry)
        else:
            assert planner_model is not None
            await run_planner(state, gov, registry, planner_model, skip_when_idle=planner_skip_when_idle)
    if gov.status is RunStatus.ABORTED:
        return result(tuple(state.requirements), ())

    # 部分結果: 検査していない要件は、理由コードつきの確認不能で必ず出す（コードが印を付ける。証拠があれば判定表が証拠を採る）
    gov.enter(Phase.ADJUDICATE)
    reverified = checker.reverify(state.requirements)  # 最終再検証: 原文に当たらなくなった引用は推測へ落ちる
    reqs = reverified.requirements
    state.requirements = list(reqs)
    marks = dict(state.marks)
    code = _DEGRADED_MARK.get(gov.degraded_reason) if gov.degraded_reason is not None else None
    if code is not None:
        for r in reqs:
            if r.kind is not Kind.SPECULATIVE and r.req_id not in marks and state.req_state(r) is ReqState.OPEN:
                marks[r.req_id] = UnverifiableMark(req_id=r.req_id, reason_code=code)
    verdicts = adjudicate(
        AdjudicationInput(
            requirements=reqs,
            docs=state.doc_metas(),
            observations=tuple(state.observations),
            marks=tuple(marks.values()),
        )
    )
    for v in verdicts:
        trace.emit(
            gov.phase, Actor.ADJUDICATOR, TraceType.VERDICT, req_id=v.req_id, verdict=v.label,
            reason_code=v.reason_code.value if v.reason_code else None,
        )  # fmt: skip
    contradictions = find_contradictions(reqs)  # 要項間の矛盾（判定表の外。最終再検証を通った引用だけで比べる）
    gov.snapshot()
    gov.enter(Phase.REPORT)
    gov.enter(Phase.DONE)
    return result(reqs, verdicts, reverified.issues, snapshot=False, contradictions=contradictions)
