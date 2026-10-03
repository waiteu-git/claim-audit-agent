"""run_check の窓口: checker 名 → チェッカー関数（設計 §4 run_check）。ネットワーク不使用・LLM 不使用・費用 0。

ToolRegistry（T7）はここだけを呼ぶ。チェッカーが使う値（字数の上限など）は引数で受けず、要件の検証済み引用から取る。
文書（SanitizedDoc）と保存済みの http_probe 観測は CheckContext で渡す。

実装済み: text_length・auth_wall・cloud_run_signature。差し込み口だけ（NotImplementedError）: leak_scan・contains_terms（G3）。
"""
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from app.checks.auth_wall import check_auth_wall
from app.checks.cloud_run_signature import check_cloud_run_signature
from app.checks.contains_terms import check_contains_terms
from app.checks.leak_scan import check_leak_scan
from app.checks.text_length import check_text_length
from app.contracts import (
    Checker,
    DocRole,
    Observation,
    ObsCode,
    ObsOutcome,
    SanitizedDoc,
    ToolName,
    VerifiedRequirement,
)


@dataclass(frozen=True)
class CheckContext:
    """チェッカーが読む保存済みの材料。"""

    docs: Mapping[str, SanitizedDoc]  # doc_id → 文書
    probes: Sequence[Observation] = ()  # 保存済みの http_probe 観測（古い順）
    target_doc_id: str | None = None  # 字数などを数える提出物の文書。None なら提出物の文書が1つだけの時にそれを使う


CheckerFn = Callable[[VerifiedRequirement, CheckContext, str], Observation]


def pick_submission_doc(ctx: CheckContext) -> tuple[SanitizedDoc | None, str]:
    """検査対象の提出物の文書を選ぶ。選べない時は (None, 理由の識別子)。"""
    if ctx.target_doc_id is not None:
        doc = ctx.docs.get(ctx.target_doc_id)
        if doc is None:
            return None, "no_such_doc"
        # 要項側の文書（spec）を提出物として測らない（取り違えで「提出物の本文は…字」と言わないため）
        return (doc, "") if doc.role is DocRole.SUBMISSION else (None, "not_submission_doc")
    subs = [d for d in ctx.docs.values() if d.role is DocRole.SUBMISSION]
    if len(subs) == 1:
        return subs[0], ""
    return None, "no_submission_doc" if not subs else "ambiguous_doc"


def _text_length(req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    doc, why = pick_submission_doc(ctx)
    if doc is None:  # 前提（検査対象の文書）が無い。不確定として返す（判定表は確認不能にする）
        return Observation(
            obs_id=obs_id,
            tool=ToolName.RUN_CHECK,
            checker=Checker.TEXT_LENGTH,
            req_id=req.req_id,
            code=ObsCode.ERROR,
            outcome=ObsOutcome.INCONCLUSIVE,
            facts={"why": why},
        )
    return check_text_length(req, doc, obs_id)


def _auth_wall(req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    return check_auth_wall(req, ctx.probes, obs_id)


def _cloud_run_signature(req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    return check_cloud_run_signature(req, ctx.probes, obs_id)


def _leak_scan(req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    return check_leak_scan(req, [d for d in ctx.docs.values() if d.role is DocRole.SUBMISSION], obs_id)


def _contains_terms(req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    doc, why = pick_submission_doc(ctx)
    if doc is None:
        return Observation(
            obs_id=obs_id,
            tool=ToolName.RUN_CHECK,
            checker=Checker.CONTAINS_TERMS,
            req_id=req.req_id,
            code=ObsCode.ERROR,
            outcome=ObsOutcome.INCONCLUSIVE,
            facts={"why": why},
        )
    return check_contains_terms(req, doc, obs_id)


CHECKERS: dict[Checker, CheckerFn] = {
    Checker.TEXT_LENGTH: _text_length,
    Checker.AUTH_WALL: _auth_wall,
    Checker.CLOUD_RUN_SIGNATURE: _cloud_run_signature,
    Checker.LEAK_SCAN: _leak_scan,
    Checker.CONTAINS_TERMS: _contains_terms,
}


def run_checker(checker: Checker, req: VerifiedRequirement, ctx: CheckContext, obs_id: str) -> Observation:
    """checker を要件に適用して、req_id 付きの観測を返す。未実装のチェッカーは NotImplementedError。"""
    return CHECKERS[checker](req, ctx, obs_id)
