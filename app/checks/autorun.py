"""AUTORUN: 前提がコード判定で揃う検査を、Planner の呼び出しと無関係に必ず実行する（設計 §3。LLM 無し・費用 0）。

  * 提出URLの http_probe を1回（認証壁・実行環境の署名が要る要件がある時）、続けて text_length・auth_wall・leak_scan・
    cloud_run_signature・contains_terms を要件の check_class に応じて走らせる（registry.run_checker を使う）。
    観測は req_id 付きで返る。計画（plan_autorun）は純関数で、同じ要件・同じ材料には必ず同じ手順を返す。
  * inspect_mode=router は同じ関数を使う（agent/autorun_phase.py）。Planner モードは AUTORUN の後に、AUTORUN で決まらなかった
    要件だけを扱う。
  * 前提が揃わない検査は走らせない（Planner／router に残す）:
      - contains_terms は、提出物の説明に「案内ページ」らしいリンク（役割 docs。コードが href のパスで付ける。ingest/sanitize）があり、
        まだ辿っていない間は走らせない。説明ページに語が無いことは、案内ページにも無いことの根拠にならない。
        見つかれば確定する検査なので、辿る材料が尽きた後（または無い時）にだけ AUTORUN が走らせる。
      - 「禁止」の要件には contains_terms を当てない（判定表も当てはめない。向きが逆）。
      - 提出URLが無ければ auth_wall・cloud_run_signature、提出物の文書が無ければ本文の検査は走らせない。
  * 「検査を減らす」方向の Reader の出力（page_class=login_wall 等・必須→任意・role=login）は、コード裏取りと一致した時だけ
    採用する。page_class は SanitizedDoc.page_class（コード算出）、kind は QuoteChecker が決めた VerifiedRequirement.kind、
    login は href のパス規則（sanitize）が正で、Reader の申告は一致の記録（confirm_page_class）にしか使わない。
    不一致は content／必須／other のまま。
各手の実行は execute に任せられる（agent 側は Governor の許可と予算・トレースを通す）。渡さなければ直接実行する。
"""
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.checks.class_screen import is_checkable_requirement
from app.checks.http_probe import http_probe
from app.checks.probe_facts import TARGET_SUBMISSION
from app.checks.registry import CheckContext, pick_submission_doc, run_checker
from app.contracts import (
    CHECK_CLASS_CHECKER,
    Checker,
    FetchPort,
    HttpProbeArgs,
    Kind,
    Observation,
    PageClass,
    RunCheckArgs,
    SanitizedDoc,
    ToolCall,
    ToolName,
    VerifiedRequirement,
)

_PROBE_CHECKERS = frozenset({Checker.AUTH_WALL, Checker.CLOUD_RUN_SIGNATURE})
_BODY_CHECKERS = frozenset({Checker.TEXT_LENGTH, Checker.LEAK_SCAN, Checker.CONTAINS_TERMS})
class StepKind(StrEnum):
    PROBE = "probe"
    CHECK = "check"


@dataclass(frozen=True)
class AutorunStep:
    kind: StepKind
    checker: Checker | None = None
    req_id: str | None = None

    def tool_call(self) -> ToolCall:
        if self.kind is StepKind.PROBE:
            return ToolCall(
                name=ToolName.HTTP_PROBE,
                args=HttpProbeArgs(target=TARGET_SUBMISSION, reason="AUTORUN: 提出URLの到達検査（認証壁・実行環境の要件のため）"),
            )
        assert self.checker is not None and self.req_id is not None
        return ToolCall(name=ToolName.RUN_CHECK, args=RunCheckArgs(checker=self.checker, req_id=self.req_id))


@dataclass(frozen=True)
class AutorunPlan:
    steps: tuple[AutorunStep, ...] = ()
    deferred: tuple[str, ...] = ()  # 前提が揃わず、Planner／router に残す要件（contains_terms の案内ページ待ち）
    cut: int = 0  # 手数の上限で計画から外した検査の数（Planner／router に残す）


def plan_autorun(
    requirements: Sequence[VerifiedRequirement],
    *,
    has_submission_url: bool,
    has_submission_doc: bool,
    defer_terms: bool = False,
    max_steps: int | None = None,
) -> AutorunPlan:
    """AUTORUN の手順。probe（必要な時だけ・先頭）→ 要件を req_id の並びで1件ずつ run_check。"""
    checks: list[AutorunStep] = []
    deferred: list[str] = []
    for r in requirements:
        if not is_checkable_requirement(r):
            continue
        checker = CHECK_CLASS_CHECKER[r.check_class]
        assert checker is not None
        if checker in _PROBE_CHECKERS and not has_submission_url:
            continue
        if checker in _BODY_CHECKERS and not has_submission_doc:
            continue
        if checker is Checker.CONTAINS_TERMS:
            if r.kind is Kind.PROHIBITED:
                continue  # 語が在ることを確かめる検査は、禁止の要件には当てはまらない
            if defer_terms:
                deferred.append(r.req_id)
                continue
        checks.append(AutorunStep(StepKind.CHECK, checker, r.req_id))
    steps = [AutorunStep(StepKind.PROBE)] if any(s.checker in _PROBE_CHECKERS for s in checks) else []
    steps += checks
    cut = 0
    if max_steps is not None and len(steps) > max_steps:
        cut = len(steps) - max(0, max_steps)
        steps = steps[: max(0, max_steps)]
    return AutorunPlan(tuple(steps), tuple(deferred), cut)


def confirm_page_class(proposed: PageClass, doc: SanitizedDoc) -> tuple[PageClass, bool]:
    """Reader が提案したページ種別の裏取り。(採る種別, 提案と一致したか) を返す。

    採る種別は常にコード算出の doc.page_class。Reader が login_wall・spa_shell などを申告しても、コードの値が content なら
    content のまま（検査を減らす方向をモデルに許さない）。逆にコードが非 content と見た文書を、Reader が content と言っても
    コードの値が残る。一致した時だけ adopted=True（記録のため）。
    """
    return doc.page_class, proposed == doc.page_class


async def autorun(
    requirements: Sequence[VerifiedRequirement],
    ctx: CheckContext,
    fetch: FetchPort,
    *,
    submission_url: str,
    next_obs_id: Callable[[], str],
    defer_terms: bool = False,
    max_steps: int | None = None,
    plan: AutorunPlan | None = None,
    execute: Callable[[AutorunStep], Awaitable[Observation | None]] | None = None,
) -> tuple[Observation, ...]:
    """計画どおりに検査を走らせ、観測（req_id 付き）を返す。

    execute を渡すと各手の実行はそれに任せる（None を返したら、その手は許可されなかった＝観測なし）。渡さない時は直接実行し、
    probe の観測は後続の auth_wall・cloud_run_signature に渡す（ctx.probes に足す）。
    """
    doc, _ = pick_submission_doc(ctx)
    plan = plan or plan_autorun(
        requirements,
        has_submission_url=bool(submission_url),
        has_submission_doc=doc is not None,
        defer_terms=defer_terms,
        max_steps=max_steps,
    )
    by_id = {r.req_id: r for r in requirements}
    probes = list(ctx.probes)
    out: list[Observation] = []
    for step in plan.steps:
        if execute is not None:
            obs = await execute(step)
        elif step.kind is StepKind.PROBE:
            obs = (await http_probe(fetch, submission_url, obs_id=next_obs_id(), target=TARGET_SUBMISSION)).observation
            probes.append(obs)
        else:
            assert step.checker is not None and step.req_id is not None
            now = CheckContext(docs=ctx.docs, probes=tuple(probes), target_doc_id=ctx.target_doc_id)
            obs = run_checker(step.checker, by_id[step.req_id], now, next_obs_id())
        if obs is not None:
            out.append(obs)
    return tuple(out)
