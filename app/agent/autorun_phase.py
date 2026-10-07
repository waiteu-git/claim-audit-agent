"""AUTORUN フェーズ（設計 §3）: READ の後・INSPECT の前に、前提がコード判定で揃う検査を必ず走らせる。LLM 無し・費用 0。

計画（何をどの順に走らせるか）は checks/autorun.py の純関数。ここはそれを Governor・ToolRegistry の上で実行する薄い層で、
Planner／router と同じ許可・同じ予算・同じトレースを通る（各手は Governor.admit → ToolRegistry.execute。tool_request・
tool_result がトレースに残り、ツール呼び出し数・取得数も計上される）。AUTORUN で決まらなかった要件（前提が揃わない・拒否された・
不確定だった）だけが INSPECT に残る。router も Planner も、この同じ関数の後に動く。

Planner に残す手数として AUTORUN_RESERVE_CALLS 回分のツール呼び出しを取っておく（実 LP のように検査できる要件が多くても、
Planner が案内ページを辿る・結論を確かめる手が残る）。
"""
from app.agent.governor import Governor
from app.agent.state import RunState
from app.agent.tools import ToolRegistry
from app.checks.autorun import AutorunPlan, AutorunStep, StepKind, autorun, confirm_page_class, plan_autorun
from app.checks.registry import CheckContext
from app.contracts import Actor, DocRole, FetchPort, LinkRole, Observation, PageClass, TraceType

AUTORUN_RESERVE_CALLS = 4


def unfollowed_docs_links(state: RunState) -> bool:
    """提出物の文書に、まだ辿っていない案内ページらしいリンクがあるか（判定は RunState.unfollowed_docs_link の1か所）。"""
    return state.unfollowed_docs_link() is not None


def _record_reader_proposals(state: RunState, gov: Governor, proposals: dict[str, PageClass]) -> None:
    """Reader が提案した「検査を減らす」方向のページ種別（content 以外）を裏取りして、一致したかを記録する。採用する値は常にコード算出。"""
    for doc_id, proposed in proposals.items():
        doc = state.docs.get(doc_id)
        if doc is None or proposed is PageClass.CONTENT:
            continue
        adopted, matched = confirm_page_class(proposed, doc)
        gov.trace.emit(
            gov.phase, Actor.VERIFIER, TraceType.AUTORUN, name="reader_proposal",
            attrs={"field": "page_class", "proposed": proposed.value, "code": adopted.value, "adopted": matched},
        )  # fmt: skip


def make_plan(state: RunState, gov: Governor) -> AutorunPlan:
    return plan_autorun(
        state.requirements,
        has_submission_url=bool(state.preset.submission_url),
        has_submission_doc=state.submission_doc_id is not None,
        defer_terms=unfollowed_docs_links(state),
        max_steps=max(0, gov.meter.caps.tool_calls - AUTORUN_RESERVE_CALLS),
    )


async def run_autorun_phase(
    state: RunState,
    gov: Governor,
    registry: ToolRegistry,
    fetch: FetchPort,
    *,
    page_class_proposals: dict[str, PageClass] | None = None,
) -> tuple[Observation, ...]:
    """AUTORUN を実行して、得た観測（state.observations にも入る）を返す。"""
    _record_reader_proposals(state, gov, page_class_proposals or {})
    plan = make_plan(state, gov)
    gov.trace.emit(
        gov.phase, Actor.GOVERNOR, TraceType.AUTORUN, name="plan",
        attrs={"steps": len(plan.steps), "deferred": len(plan.deferred), "cut": plan.cut,
               "probe": any(s.kind is StepKind.PROBE for s in plan.steps)},
    )  # fmt: skip
    turn = 0
    max_turns = gov.meter.caps.tool_calls + 1

    async def execute(step: AutorunStep) -> Observation | None:
        nonlocal turn
        if step.kind is StepKind.CHECK:
            req = state.req(step.req_id or "")
            if req is not None and state.needs_probe_first(req):
                return None  # probe が許可されなかった。依存する検査は走らせない（PROBE_FIRST の拒否を重ねて拒否の連続にしない）
        turn += 1
        if gov.check_stop():
            return None
        gov.begin_turn(turn, max_turns, gov.allowed_tools())
        adm = gov.admit(step.tool_call())
        if not adm.allowed:
            return None
        return (await registry.execute(adm)).observation

    ctx = CheckContext(docs=dict(state.docs), probes=state.probes(), target_doc_id=state.submission_doc_id)
    return await autorun(
        state.requirements, ctx, fetch, submission_url=state.preset.submission_url or "", next_obs_id=state.next_obs_id,
        plan=plan, execute=execute,
    )  # fmt: skip
