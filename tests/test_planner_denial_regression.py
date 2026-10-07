"""第3弾 1-0: Planner が「許可リストに出ているのに通らない」mark_unverifiable を出し続けて DEGRADED になる劣化の回帰試験。

10/7 のライブ実行（実LP）で、Planner は毎ターン mark_unverifiable を NO_EVIDENCE などコード専用の理由で呼び、Governor が
P-UNVERIF-01 / CODE_ONLY で拒否 → 拒否の連続（DENIAL_STREAK）で DEGRADED になった。router は同じ条件で DONE。
直し方（a）: 関数宣言の reason_code を PLANNER_MARK_CODES の列挙に絞り、システム指示にも書く（モデルが選べる値＝通る値）。
加えて（b）: 印を付けられる要件が無い間は mark_unverifiable を許可リストから外す（検査前の要件だけ＝CHECK_FIRST で必ず拒否される）。
拒否されたら StateView に直前の拒否の理由（DenialCode）を載せ、同じ呼び出しの繰り返しは P-DUP-01 / REPEATED_DENIAL で即座に止める。
"""
import json

from app.agent.governor import PLANNER_MARK_CODES
from app.agent.planner import PLANNER_SYSTEM, run_planner
from app.agent.tools import ToolRegistry, mark_unverifiable_schema
from app.config import RUN_CAPS
from app.contracts import (
    CheckClass,
    Decision,
    DegradedReason,
    DenialCode,
    Kind,
    ModelRequest,
    ModelResponse,
    PolicyId,
    RunStatus,
    ToolName,
    UnverifiableReason,
)
from app.model.scripted import ScriptedPort, reply_calls
from tests.agent_support import AUTH_SENTENCE, LANG_SENTENCE, LEN_SENTENCE, make_world, raw, standard_fetch

REQS = (
    raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),
    raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
    raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE),  # 検査の種類が無い要件（ライブでは Planner がここへ印を付けようとした）
)


def setup(reqs=REQS, caps=RUN_CAPS):
    state, gov = make_world(caps=caps, reqs=reqs, submission_text="あ" * 120)
    return state, gov, ToolRegistry(state=state, governor=gov, fetch=standard_fetch())


def denials(gov):
    return [(e.policy_id, e.reason_code) for e in gov.trace.events if e.decision is Decision.DENY]


def _mark_decl(req: ModelRequest) -> dict | None:
    for t in req.tools:
        if t.name is ToolName.MARK_UNVERIFIABLE:
            return t.parameters
    return None


def live_like_marker(req: ModelRequest) -> ModelResponse:
    """ライブの Planner の癖を再現する台本: 印が許可されていれば、宣言の列挙から「根拠なし」に近い理由を選んで R3 に付ける。

    修正前は宣言が契約の12語をそのまま持っていたので NO_EVIDENCE を選べた（→ CODE_ONLY で拒否）。修正後は列挙に無いので選べない。
    """
    params = _mark_decl(req)
    if params is None:
        return reply_calls(("finish", {}))
    enum = params["properties"]["reason_code"]["enum"]
    code = "NO_EVIDENCE" if "NO_EVIDENCE" in enum else "HUMAN_ONLY"
    return reply_calls(("mark_unverifiable", {"req_id": "R3", "reason_code": code}))


# ---- (a) 宣言のスキーマ -----------------------------------------------------------------------------
def test_the_declared_reason_codes_are_exactly_the_ones_the_governor_accepts():
    schema = mark_unverifiable_schema()
    assert set(schema["properties"]["reason_code"]["enum"]) == {c.value for c in PLANNER_MARK_CODES}
    for code_only in (UnverifiableReason.NO_EVIDENCE, UnverifiableReason.BUDGET, UnverifiableReason.TRUNCATED):
        assert code_only.value not in schema["properties"]["reason_code"]["enum"]
    assert "maxItems" not in json.dumps(schema)  # Vertex が 400 を返す（実測済み）


def test_req_ids_in_the_declaration_are_narrowed_to_markable_requirements():
    state, gov, reg = setup()
    gov.begin_turn(1, 8, gov.allowed_tools())
    assert gov.markable_reqs() == ["R3"]  # R1・R2 は検査前（CHECK_FIRST）なので印を付けられない
    (decl,) = [d for d in reg.declarations(gov.allowed_tools(), mark_req_ids=tuple(gov.markable_reqs())) if d.name is ToolName.MARK_UNVERIFIABLE]
    assert decl.parameters["properties"]["req_id"]["enum"] == ["R3"]


def test_the_system_instruction_names_the_rule():
    assert "reason_code" in PLANNER_SYSTEM and "last_denial" in PLANNER_SYSTEM


# ---- (b) 許可リスト ---------------------------------------------------------------------------------
def test_mark_unverifiable_is_not_offered_when_only_unchecked_checkable_requirements_remain():
    state, gov, reg = setup(reqs=REQS[:2])
    assert ToolName.MARK_UNVERIFIABLE not in gov.allowed_tools()
    assert ToolName.MARK_UNVERIFIABLE not in {d.name for d in reg.declarations(gov.allowed_tools())}


# ---- 再現: 拒否されるツールを3回出す Planner --------------------------------------------------------
async def test_reproduction_a_planner_repeating_a_denied_call_three_times_degrades_and_sees_the_reason():
    """修正後も、宣言を無視して同じ拒否される呼び出しを出し続けるモデルは止まる（2回目からは REPEATED_DENIAL で即座に拒否）。"""
    state, gov, reg = setup(reqs=REQS[2:])  # 検査の種類が無い要件だけ
    bad = ("mark_unverifiable", {"req_id": "R1", "reason_code": "NO_EVIDENCE"})
    port = ScriptedPort([reply_calls(bad)] * 3)
    await run_planner(state, gov, reg, port)
    assert (gov.status, gov.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.DENIAL_STREAK)
    assert denials(gov) == [(PolicyId.UNVERIF, "CODE_ONLY"), (PolicyId.DUP, "REPEATED_DENIAL"), (PolicyId.DUP, "REPEATED_DENIAL")]
    # 2ターン目以降の StateView には、直前の拒否の理由と関数名が載っている（1ターン目は無い）
    views = [json.loads(r.contents) for r in port.requests]
    assert views[0]["last_denial"] is None
    assert (views[1]["last_denial"], views[1]["last_denied_tool"]) == (DenialCode.CODE_ONLY.value, "mark_unverifiable")
    assert views[2]["last_denial"] == DenialCode.REPEATED_DENIAL.value


async def test_after_the_fix_a_live_like_planner_is_never_denied_and_finishes_done():
    """ライブと同じ癖（印を付けたがる）の Planner でも、宣言に通る理由しか無いので拒否が起きず、検査を済ませて DONE になる。"""
    state, gov, reg = setup()
    steps = [
        reply_calls(("http_probe", {"target": "SUBMISSION_URL", "reason": "到達検査"})),
        reply_calls(("run_check", {"checker": "auth_wall", "req_id": "R2"})),
        reply_calls(("run_check", {"checker": "text_length", "req_id": "R1"})),
        live_like_marker,  # 宣言から理由を選ぶ（修正前なら NO_EVIDENCE を選んで拒否されていた）
        live_like_marker,  # R3 に印が付いたので、もう宣言に mark_unverifiable は無い → finish
    ]
    port = ScriptedPort(steps)
    await run_planner(state, gov, reg, port)
    assert denials(gov) == []
    assert gov.status is RunStatus.DONE
    assert state.marks["R3"].reason_code is UnverifiableReason.HUMAN_ONLY
    assert _mark_decl(port.requests[-1]) is None  # 最後のターンには印の宣言が無い


async def test_a_denied_call_may_be_retried_once_the_state_has_changed():
    """繰り返しの即時拒否は「何も変わっていない」時だけ。検査が走って状態が変われば、同じ呼び出しを改めて審査する。"""
    state, gov, _ = setup()
    gov.begin_turn(1, 8, tuple(ToolName))  # 古い許可リスト（宣言を無視するモデル）を想定
    from app.contracts import FunctionCall, Observation, ObsCode, ObsOutcome

    call = FunctionCall(name="mark_unverifiable", args={"req_id": "R1", "reason_code": "HUMAN_ONLY"})
    assert gov.admit(call).reason == "CHECK_FIRST"
    assert gov.admit(call).reason == "REPEATED_DENIAL"
    state.observations.append(
        Observation(obs_id="O1", tool=ToolName.RUN_CHECK, checker="text_length", req_id="R1",  # type: ignore[arg-type]
                    code=ObsCode.LIMIT_UNDECIDABLE, outcome=ObsOutcome.INCONCLUSIVE)
    )
    assert gov.admit(call).allowed  # 検査が不確定だった後なので通る
    assert gov.last_denial is None and gov.last_denied_tool is None  # 許可で直前の拒否は消える


async def test_finish_is_not_blocked_as_a_repeat_because_its_timing_changes():
    state, gov, _ = setup()
    from app.contracts import FunctionCall

    gov.begin_turn(1, 2, gov.allowed_tools())
    assert gov.admit(FunctionCall(name="finish")).reason == "OPEN_REQUIREMENTS"
    gov.begin_turn(2, 2, gov.allowed_tools())  # 最終ターン
    assert gov.admit(FunctionCall(name="finish")).allowed
