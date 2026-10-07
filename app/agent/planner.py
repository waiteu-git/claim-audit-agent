"""Planner ループと router（設計 §2・§3）。どちらも同じ Governor・同じ ToolRegistry で動く（INSPECT フェーズ）。

Planner（inspect_mode=planner）: LLM が関数呼び出しで検査を進める。**手動の function calling**（自動実行は使わない）で、
モデルが返した関数呼び出しは1つずつ Governor の許可（admit）を通ってから ToolRegistry が実行する。
  * Planner が毎ターン見るのは StateView（約3KB。ID と enum と数値だけ）が唯一の入力。生テキスト・要件の自由文・
    リンクのアンカー文言・注入フラグの内容は型に載らない（StateView が自由文のフィールドを持たない）。履歴も渡さない。
  * 呼べる関数はターンごとに Governor が決める許可リスト。宣言（tools）もその許可リストから作る。
router（inspect_mode=router）: LLM 無し。要件の check_class から決まる検査を、決まった順に Governor 経由で走らせる。
  Planner が不安定な時の代替であり、A/B 比較の対照。Planner と同じ上限・同じ拒否規則・同じツールを通る。

どちらも判定は書かない。観測が溜まるだけで、判定は adjudicate.py（INSPECT の後）。
"""
import asyncio
import re
from enum import StrEnum

from app.agent.budget import estimate_tokens
from app.agent.governor import Governor
from app.agent.state import RunState
from app.agent.tools import ToolRegistry
from app.contracts import (
    CHECK_CLASS_CHECKER,
    STATE_VIEW_TARGET_BYTES,
    AbortReason,
    Actor,
    CheckClass,
    DegradedReason,
    DocFeatures,
    FeatureCategory,
    FinishArgs,
    HttpProbeArgs,
    LinkRole,
    ModelPurpose,
    ModelRequest,
    ReqState,
    RunCheckArgs,
    SanitizedDoc,
    StateDoc,
    StateLink,
    StateRequirement,
    StateView,
    ToolCall,
    ToolName,
    TraceType,
    VerifiedRequirement,
)
from app.errors import ErrorCode, classify
from app.model.port import ModelPort

PLANNER_MAX_OUTPUT_TOKENS = 512  # thinking を含む。関数呼び出しだけなので小さい
MAX_CALLS_PER_TURN = 4  # 1ターンで処理する関数呼び出しの数。超えた分は黙って捨てる（予算は呼び出しごとに計上される）

PLANNER_SYSTEM = (
    "あなたは、提出物の検査を進める司令役です。入力は状態の JSON だけで、文書の本文も要件の文章も見えません"
    "（ID・種別・件数・予算だけ）。allowed_tools の関数だけを呼んでください。\n"
    "- requirements の routes は検査の手順の候補です。state が open の要件から進めてください。\n"
    "- 検査できる要件にひとつも着手していない間は finish できません。\n"
    "- 判定（適合・不適合）は書きません。判定は観測からコードが決めます。\n"
    "- mark_unverifiable の reason_code は宣言に列挙された値だけです（NO_EVIDENCE・BUDGET などはコードが付けます）。"
    "検査できる要件には、検査が不確定だった後にだけ付けられます。\n"
    "- last_denial があれば、直前の呼び出しはその理由で拒否されています。同じ呼び出しを繰り返さず、別の手か finish に移ってください。\n"
    "自由文は出力せず、関数呼び出しだけを返してください。"
)


class InspectMode(StrEnum):
    PLANNER = "planner"
    ROUTER = "router"


# ---- StateView ---------------------------------------------------------------------------------------
_FEATURE_VOCAB: dict[FeatureCategory, re.Pattern[str]] = {
    FeatureCategory.ACCOUNT: re.compile(r"アカウント|account", re.I),
    FeatureCategory.AUTH: re.compile(r"ログイン|認証|log\s*-?in|auth", re.I),
    FeatureCategory.DEMO: re.compile(r"デモ|demo", re.I),
    FeatureCategory.VIDEO: re.compile(r"動画|ビデオ|video|youtube", re.I),
    FeatureCategory.LICENSE: re.compile(r"ライセンス|license", re.I),
    FeatureCategory.DEADLINE: re.compile(r"締切|期限|deadline", re.I),
    FeatureCategory.CHAR_LIMIT: re.compile(r"文字以内|字以内|文字数|字数|characters?", re.I),
    FeatureCategory.REPOSITORY: re.compile(r"リポジトリ|repositor|github", re.I),
    FeatureCategory.DEPLOY: re.compile(r"デプロイ|deploy|cloud\s*run", re.I),
    FeatureCategory.CONTACT: re.compile(r"問い合わせ|連絡|contact", re.I),
    FeatureCategory.URL: re.compile(r"https?://|URL", re.I),
    FeatureCategory.GUIDANCE: re.compile(r"手順|案内|使い方|guide|instruction", re.I),
}


def compute_features(doc: SanitizedDoc, state: RunState) -> DocFeatures:
    """コード算出の文書特徴（長さ・語彙カテゴリの命中数・リンクの役割別の数）。数値だけで、本文を載せない。"""
    hits = {c: min(99, len(p.findall(doc.visible_text))) for c, p in _FEATURE_VOCAB.items()}
    roles: dict = {}
    for ref in state.links_of(doc.doc_id):
        roles[ref.entry.role] = roles.get(ref.entry.role, 0) + 1
    return DocFeatures(
        length=len(doc.visible_text),
        category_hits={c: n for c, n in hits.items() if n > 0},
        link_role_counts=roles,
    )


def routes_for(state: RunState, req: VerifiedRequirement) -> tuple[str, ...]:
    """要件の検査の手順の候補（code が表から決める。Planner はこの中から選ぶ）。検査できない要件は空。"""
    if not state.is_checkable(req):
        return ()
    checker = CHECK_CLASS_CHECKER[req.check_class]
    assert checker is not None
    needs_probe = req.check_class in (CheckClass.AUTH_WALL, CheckClass.RUNTIME_SIGNATURE)
    return (("http_probe:SUBMISSION_URL",) if needs_probe else ()) + (f"run_check:{checker.value}",)


def _req_order(r: StateRequirement) -> tuple[int, int]:
    return (0 if r.state is ReqState.OPEN else 1, int(r.req_id[1:]))


def build_state_view(state: RunState, gov: Governor, turn: int, max_turns: int, allowed: tuple[ToolName, ...]) -> StateView:
    """Planner の唯一の入力。約3KB（STATE_VIEW_TARGET_BYTES）に収まるまで、重要でない行から間引く。

    間引きの順: 手順の候補 → 完了済みの要件 → スコープ外のリンク → 取得済み・ログインのリンク → open の要件の後ろ。
    Planner が見えなかった要件も、router・adjudicate は全件を扱う（間引きは見せ方だけで、判定に影響しない）。
    """
    reqs_all = sorted(
        (
            StateRequirement(
                req_id=r.req_id,
                kind=r.kind,
                check_class=r.check_class,
                state=state.req_state(r),
                routes=routes_for(state, r),
                calls_used=min(3, state.calls_used(r.req_id)),
            )
            for r in state.requirements
        ),
        key=_req_order,
    )
    docs = tuple(
        StateDoc(
            doc_id=d.doc_id,
            role=d.role,
            page_class=d.page_class,
            truncated=d.truncated or d.doc_id in state.unread_doc_ids,
            features=compute_features(d, state),
        )
        for d in state.docs.values()
    )
    links_all = sorted(
        (
            StateLink(link_id=gid, role=r.entry.role, in_scope=r.entry.in_scope, fetched=gid in state.fetched_links)
            for gid, r in state.links.items()
        ),
        key=lambda lk: (not lk.in_scope, lk.fetched, int(lk.link_id[1:])),
    )

    def make(reqs: list[StateRequirement], links: list[StateLink], routes: bool, docs_: tuple[StateDoc, ...] = docs) -> StateView:
        rows = tuple(r if routes else r.model_copy(update={"routes": ()}) for r in reqs)
        return StateView(
            turn=turn,
            max_turns=max_turns,
            allowed_tools=allowed,
            requirements=rows,
            docs=docs_,
            links=tuple(links),
            budget=gov.meter.budget.snapshot(),
            last_observation=state.last_observation,
            last_denial=gov.last_denial,
            last_denied_tool=gov.last_denied_tool,
        )

    open_reqs = [r for r in reqs_all if r.state is ReqState.OPEN]
    in_scope_links = [lk for lk in links_all if lk.in_scope]
    attempts = [
        (reqs_all, links_all, True),
        (reqs_all, links_all, False),
        (open_reqs, links_all, False),
        (open_reqs, in_scope_links, False),
        (open_reqs, [lk for lk in in_scope_links if not lk.fetched and lk.role is not LinkRole.LOGIN], False),
    ]
    for a in attempts:
        view = make(*a)
        if view.size_bytes() <= STATE_VIEW_TARGET_BYTES:
            return view
    # それでも超える時の最後の手段: 後ろの行から1つずつ落とす（open の要件は先頭の8件まで残す。文書は最後に）
    reqs, links, docs_l = list(attempts[-1][0]), list(attempts[-1][1]), list(docs)
    view = make(reqs, links, False, tuple(docs_l))
    while view.size_bytes() > STATE_VIEW_TARGET_BYTES and (reqs or links or docs_l):
        if len(reqs) > 8:
            reqs.pop()
        elif links:
            links.pop()
        elif len(docs_l) > 2:
            docs_l.pop()
        elif reqs:
            reqs.pop()
        else:
            docs_l.pop()
        view = make(reqs, links, False, tuple(docs_l))
    return view


# ---- Planner ループ ----------------------------------------------------------------------------------
async def run_planner(state: RunState, gov: Governor, registry: ToolRegistry, model: ModelPort) -> None:
    """INSPECT。最大 planner_max_turns ターン。終わり方は finish・停止条件（Governor.check_stop）・ターン切れのどれか。"""
    caps = gov.meter.caps
    for turn in range(1, caps.planner_max_turns + 1):
        if gov.check_stop():
            return
        allowed = gov.allowed_tools()
        gov.begin_turn(turn, caps.planner_max_turns, allowed)
        view = build_state_view(state, gov, turn, caps.planner_max_turns, allowed)
        gov.trace.emit(gov.phase, Actor.GOVERNOR, TraceType.STATE_VIEW, state_view=view)

        contents = view.to_prompt_json()
        req = ModelRequest(
            purpose=ModelPurpose.PLANNER,
            system=PLANNER_SYSTEM,
            contents=contents,  # StateView の JSON だけ。生テキストは経路に無い
            tools=registry.declarations(allowed, mark_req_ids=tuple(gov.markable_reqs())),
            allowed_tool_names=allowed,
            max_output_tokens=PLANNER_MAX_OUTPUT_TOKENS,
            thinking_budget=caps.thinking_budget_planner,
            timeout_s=caps.model_call_timeout_s,
        )
        res = gov.reserve_model(ModelPurpose.PLANNER, estimate_tokens(PLANNER_SYSTEM + contents), PLANNER_MAX_OUTPUT_TOKENS)
        if res is None:
            gov.degrade(DegradedReason.BUDGET)  # KILL・WALL_CLOCK の時は reserve_model が ABORTED にしている（degrade は上書きしない）
            return
        try:
            resp = await model.generate(req)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001  分類した ErrorCode だけを残す
            code = classify(e)
            gov.settle_model(res, None, model_id=model.model_id, error_code=code.value)
            if code is ErrorCode.FATAL_CONFIG:
                raise
            if code is ErrorCode.KILLED:
                gov.abort(AbortReason.KILL)
            else:
                gov.degrade(DegradedReason.MODEL_FAILURE)
            return
        gov.settle_model(res, resp, model_id=model.model_id)

        if not resp.function_calls:
            gov.deny_no_call()  # 関数を呼ばない応答は拒否として数える（自由文では何も実行されない）
        for raw in resp.function_calls[:MAX_CALLS_PER_TURN]:
            adm = gov.admit(raw)
            if gov.stopped:
                return
            if not adm.allowed:
                continue
            result = await registry.execute(adm)
            if result.finished:
                gov.snapshot()
                return
        gov.snapshot()
    # ターン切れ: 検査できるのに未着手の要件が残っていれば、予算切れとして部分結果にする
    if gov.pending_checks():
        gov.degrade(DegradedReason.BUDGET)


# ---- router ------------------------------------------------------------------------------------------
async def run_router(state: RunState, gov: Governor, registry: ToolRegistry) -> None:
    """LLM 無しの決定論の検査。Planner と同じ Governor・同じツールを通る。

    順序: 提出URLの到達検査（認証壁・実行環境の署名が要る要件がある時だけ）→ 検査できる要件を req_id 順に run_check → finish。
    """
    turn = 0
    max_turns = gov.meter.caps.tool_calls + 1

    async def call(tc: ToolCall) -> None:
        nonlocal turn
        turn += 1
        if gov.check_stop():
            return
        gov.begin_turn(turn, max_turns, gov.allowed_tools())
        adm = gov.admit(tc)
        if adm.allowed:
            await registry.execute(adm)

    pending = gov.pending_checks()
    needs_probe = any(
        (r := state.req(rid)) is not None and r.check_class in (CheckClass.AUTH_WALL, CheckClass.RUNTIME_SIGNATURE)
        for rid in pending
    )
    if needs_probe and state.preset.submission_url:
        await call(
            ToolCall(
                name=ToolName.HTTP_PROBE,
                args=HttpProbeArgs(target="SUBMISSION_URL", reason="router: 提出URLの到達検査（認証壁・実行環境の要件のため）"),
            )
        )
    for rid in pending:
        req = state.req(rid)
        assert req is not None
        checker = CHECK_CLASS_CHECKER[req.check_class]
        assert checker is not None
        await call(ToolCall(name=ToolName.RUN_CHECK, args=RunCheckArgs(checker=checker, req_id=rid)))
        if gov.stopped:
            return
    await call(ToolCall(name=ToolName.FINISH, args=FinishArgs()))
    gov.snapshot()
