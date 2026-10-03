"""ACQUIRE: プリセットが固定した URL（要項のシードと提出URL）を取得して洗浄し、文書として RunState へ入れる（設計 §3）。

取得は FetchPort だけを通る（外向き HTTP の唯一の出口。スコープ・SSRF 検査は FetchPort 実装側）。プリセットの URL 以外は
取らない（公開面の入力はプリセット ID だけ＝閉世界）。取得の上限は予算の ACQUIRE 3回。取れなかった文書は作らず、
理由をトレースに残して次へ進む（要項が1つも取れなければ要件は0件で、その旨が判定に出る）。
"""
import asyncio

from app.agent.governor import Governor
from app.agent.state import RunState
from app.contracts import (
    Actor,
    ContentKind,
    DegradedReason,
    DocRole,
    FetchKind,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    FetchResult,
    TraceType,
)
from app.errors import classify
from app.ingest.sanitize import sanitize


async def acquire(state: RunState, gov: Governor, fetch: FetchPort) -> None:
    p = state.preset
    targets: list[tuple[str, DocRole, str]] = [
        (url, DocRole.SPEC, f"要項 {i}") for i, url in enumerate(p.spec_seed_urls, start=1)
    ]
    if p.submission_url:
        targets.append((p.submission_url, DocRole.SUBMISSION, "提出物"))
    cap = gov.meter.caps.fetches_acquire
    if len(targets) > cap:
        # 取得は ACQUIRE の枠（3回）まで。要項のシードが多い時は、検査の対象である提出物を残し、末尾の要項シードを落とす
        # （枠の外へ出て DEGRADED になり、READ まで飛ばされるより、読める要項を読む方がよい）
        keep_spec = cap - (1 if p.submission_url else 0)
        specs = [t for t in targets if t[1] is DocRole.SPEC][:keep_spec]
        targets = specs + [t for t in targets if t[1] is DocRole.SUBMISSION]
        gov.trace.emit(gov.phase, Actor.GOVERNOR, TraceType.PHASE_ENTER, name="ACQUIRE", flags=("seeds_trimmed",))
    for url, role, label in targets:
        if gov.check_stop():
            return
        if not gov.meter.budget.can_fetch(kind=FetchKind.ACQUIRE):
            gov.degrade(DegradedReason.BUDGET)
            return
        result: FetchResult | None = None
        code = "fetched"
        try:
            result = await fetch.fetch(FetchRequest(url=url))
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001  取得層の想定外。分類した ErrorCode だけを残す
            code = classify(e).value.lower()
        finally:
            gov.charge_fetches(FetchKind.ACQUIRE, 1, url)
        if result is not None:
            code = result.outcome.value
        gov.trace.emit(
            gov.phase, Actor.TOOL, TraceType.TOOL_RESULT, name="acquire", reason_code=code,
            bytes=len(result.body) if result is not None else None,
        )  # fmt: skip
        if result is None or result.outcome is not FetchOutcome.OK or result.content_kind is ContentKind.UNSUPPORTED:
            continue
        try:
            doc = sanitize(result, doc_id=state.next_doc_id(), role=role, label=label, scope=p.allowed_prefixes)
        except ValueError:
            continue
        state.add_doc(doc)
