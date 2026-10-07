"""テスト用の組み立て関数。契約型の最小の有効インスタンスを作る（他モジュールのテストからも使える）。

VerificationSeal は本来 DocIndex（quotes.py）だけが発行する。テストの組み立て用にここでも発行するが、
発行点を grep で固定するテスト（test_layout.py）は tests/ を許可している。
"""
import hashlib
from datetime import UTC, datetime
from typing import Any

from app.config import RUN_CAPS
from app.contracts import (
    Actor,
    Budget,
    BudgetSnapshot,
    CheckClass,
    DocMeta,
    DocRole,
    EnvName,
    Kind,
    LinkEntry,
    ModelPurpose,
    ModelRequest,
    PageClass,
    ReaderOutput,
    Phase,
    RunMode,
    RunRecord,
    RunStatus,
    RunSummary,
    SanitizedDoc,
    ToolDecl,
    ToolName,
    TraceEvent,
    TraceType,
    UnverifiableReason,
    VerificationSeal,
    Verdict,
    VerdictLabel,
    VerifiedRequirement,
    VerifiedSpan,
)
from app.textsafe import BLOCK_SEP

RUN_ID = "run_AAAAAAAAAAAAAAAAAAAAAA"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def seal() -> VerificationSeal:
    return VerificationSeal.issue("tests.factories")


def make_doc(
    doc_id: str = "D1",
    text: str = f"応募要項{BLOCK_SEP}提出物の説明は800字以内とする。{BLOCK_SEP}締切は10月15日である。",
    *,
    role: DocRole = DocRole.SPEC,
    links: tuple[LinkEntry, ...] = (),
    **kw: Any,
) -> SanitizedDoc:
    base: dict[str, Any] = dict(
        doc_id=doc_id,
        role=role,
        label="架空の要項",
        url="https://spec.example.invalid/rules",
        sha256=sha(text),
        byte_length=len(text.encode("utf-8")),
        page_class=PageClass.CONTENT,
        visible_text=text,
        links=links,
    )
    base.update(kw)
    return SanitizedDoc(**base)


def make_span(doc: SanitizedDoc, needle: str, *, occurrences: int = 1) -> VerifiedSpan:
    start = doc.visible_text.index(needle)
    return VerifiedSpan(
        doc_id=doc.doc_id, start=start, end=start + len(needle), original_span=needle, occurrences=occurrences
    )


def make_verified(
    req_id: str = "R1",
    *,
    doc: SanitizedDoc | None = None,
    needle: str = "提出物の説明は800字以内とする。",
    kind: Kind = Kind.REQUIRED,
    **kw: Any,
) -> VerifiedRequirement:
    d = doc or make_doc()
    base: dict[str, Any] = dict(
        req_id=req_id,
        kind=kind,
        declared_kind=kind,
        check_class=CheckClass.LENGTH_LIMIT,
        span=make_span(d, needle),
    )
    base.update(kw)
    return VerifiedRequirement(seal=seal(), **base)


def make_event(seq: int = 0, **kw: Any) -> TraceEvent:
    base: dict[str, Any] = dict(
        run_id=RUN_ID,
        seq=seq,
        t_ms=seq * 10,
        phase=Phase.ACQUIRE,
        actor=Actor.GOVERNOR,
        type=TraceType.PHASE_ENTER,
        name="ACQUIRE",
    )
    base.update(kw)
    return TraceEvent(**base)


def make_budget(**kw: Any) -> Budget:
    return Budget(caps=RUN_CAPS, **kw)


def make_snapshot() -> BudgetSnapshot:
    return make_budget().snapshot()


def auto_verdict(req: VerifiedRequirement) -> Verdict:
    """全要件に判定が要る規則を満たすための既定の判定（推測は参考、他は人の判断が要る確認不能）。"""
    if req.kind is Kind.SPECULATIVE:
        return Verdict(req_id=req.req_id, label=VerdictLabel.REFERENCE)
    return Verdict(req_id=req.req_id, label=VerdictLabel.UNVERIFIABLE, reason_code=UnverifiableReason.HUMAN_ONLY)


def make_record(**kw: Any) -> RunRecord:
    """最小の有効な RunRecord。requirements / docs / verdicts / summary は省略すると整合する値を作る。"""
    doc = make_doc()
    reqs = kw.pop("requirements", None) or (make_verified(doc=doc),)
    docs = kw.pop("docs", None) or (doc.meta(),)
    verdicts = kw.pop("verdicts", None)
    if verdicts is None:
        verdicts = tuple(auto_verdict(r) for r in reqs)
    contradictions = kw.pop("contradictions", ())
    injection = kw.pop("injection_signals", ())
    events = kw.pop("events", ())
    summary = kw.pop("summary", None) or RunSummary.compute(reqs, verdicts, contradictions, injection, events)
    base: dict[str, Any] = dict(
        run_id=RUN_ID,
        env=EnvName.DEV,
        mode=RunMode.LIVE,
        status=RunStatus.DONE,
        preset_id="sample_defect",
        prompt_version="dev",
        reader_model="scripted-model",
        planner_model="scripted-model",
        started_at=datetime(2026, 10, 2, 12, 0, tzinfo=UTC),
        docs=docs,
        requirements=reqs,
        verdicts=verdicts,
        contradictions=contradictions,
        injection_signals=injection,
        events=events,
        summary=summary,
        budget=make_snapshot(),
    )
    base.update(kw)
    return RunRecord(**base)


def doc_meta(doc: SanitizedDoc) -> DocMeta:
    return doc.meta()


def reader_request(**kw: Any) -> ModelRequest:
    base: dict[str, Any] = dict(
        purpose=ModelPurpose.READER, system="sys", contents="文書", response_model=ReaderOutput,
        max_output_tokens=1000, thinking_budget=RUN_CAPS.thinking_budget_reader, timeout_s=25.0,
    )  # fmt: skip
    base.update(kw)
    return ModelRequest(**base)


def planner_request(**kw: Any) -> ModelRequest:
    decl = ToolDecl.for_tool(ToolName.FINISH, "終了")
    base: dict[str, Any] = dict(
        purpose=ModelPurpose.PLANNER, system="sys", contents="{}", tools=(decl,),
        allowed_tool_names=(ToolName.FINISH,), max_output_tokens=300, thinking_budget=512, timeout_s=25.0,
    )  # fmt: skip
    base.update(kw)
    return ModelRequest(**base)
