"""第4弾 1: 実 Gemini（10/7 実測）で Planner だけが完走しなかった2つの劣化を ScriptedPort で再現し、直ったことを示す。

(1) NO_CALL: thinking（512）が出力枠（512）を使い切り、関数呼び出しが出ないまま応答が止まる。
    直し方: Planner の thinking を 0 にし、出力枠を 1,024 に広げた（理由は app/agent/planner.py の PLANNER_MAX_OUTPUT_TOKENS）。
(2) run_check → ERROR: 検査の材料（提出URL・提出物の文書）が無い要件に run_check を出し、チェッカーが ERROR を返す。
    直し方: 材料が無い要件は StateView の routes に出さず、run_check の許可リストからも外す（RunState.can_run_check）。
router と同じ条件で、Planner も「拒否0・ERROR 0・finish まで到達して DONE」になることを確かめる。
"""
import json

from app.agent.planner import PLANNER_MAX_OUTPUT_TOKENS, run_planner, run_router
from app.agent.tools import ToolRegistry
from app.config import RUN_CAPS
from app.contracts import CheckClass, Decision, Kind, ModelRequest, ModelResponse, ObsCode, RunStatus, ToolName, Usage
from app.model.scripted import ScriptedPort, reply_calls
from tests.agent_support import AUTH_SENTENCE, LANG_SENTENCE, LEN_SENTENCE, make_world, raw, standard_fetch

REQS = (
    raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),
    raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
    raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE),  # 検査の手段が無い要件
)


def setup(*, no_submission_doc: bool = False, caps=RUN_CAPS):
    state, gov = make_world(caps=caps, reqs=REQS, submission_text="あ" * 120)
    if no_submission_doc:
        state.submission_doc_id = None  # 提出物の文書が取れなかった実行
    return state, gov, ToolRegistry(state=state, governor=gov, fetch=standard_fetch())


def denials(gov):
    return [(e.policy_id, e.reason_code) for e in gov.trace.events if e.decision is Decision.DENY]


def make_follower():
    """StateView の routes と allowed_tools だけを見て進める Planner。出力枠が thinking に食われる実モデルの癖も再現する。"""
    done: set[str] = set()

    def follower(req: ModelRequest) -> ModelResponse:
        if (req.thinking_budget or 0) >= req.max_output_tokens - 16:  # 10/7: thinking が枠を使い切って、関数呼び出しが出ない
            return ModelResponse(
                model="scripted-model",
                usage=Usage(prompt_tokens=100, candidates_tokens=0, thoughts_tokens=509),
                finish_reason="MAX_TOKENS",
            )
        view = json.loads(req.contents)
        for r in view["requirements"]:
            if r["state"] != "open":
                continue
            for route in r["routes"]:  # 手順の候補（"http_probe:SUBMISSION_URL"・"run_check:auth_wall" など）
                tool, _, arg = route.partition(":")
                key = f"{tool}:{arg}:{r['req_id']}"
                if key in done or tool not in view["allowed_tools"]:
                    continue
                done.add(key)
                if tool == "http_probe":
                    return reply_calls(("http_probe", {"target": arg, "reason": "到達検査"}))
                return reply_calls(("run_check", {"checker": arg, "req_id": r["req_id"]}))
        return reply_calls(("finish", {}))

    return follower


def test_the_planner_has_room_for_a_function_call_after_thinking():
    assert RUN_CAPS.thinking_budget_planner == 0
    assert PLANNER_MAX_OUTPUT_TOKENS - RUN_CAPS.thinking_budget_planner >= 256


async def test_starved_planner_reproduces_no_call_when_thinking_eats_the_output_budget():
    """修正前の設定（thinking 512・枠 512）を再現: 毎ターン関数呼び出しが無く、NO_CALL が3回続いて DEGRADED。"""
    state, gov, reg = setup(caps=RUN_CAPS.model_copy(update={"thinking_budget_planner": 512}))
    import app.agent.planner as planner

    old = planner.PLANNER_MAX_OUTPUT_TOKENS
    planner.PLANNER_MAX_OUTPUT_TOKENS = 512
    try:
        await run_planner(state, gov, reg, ScriptedPort([make_follower()] * 8))
    finally:
        planner.PLANNER_MAX_OUTPUT_TOKENS = old
    assert gov.status is RunStatus.DEGRADED
    assert {r for _, r in denials(gov)} == {"NO_CALL"}


async def test_planner_with_the_fixed_budget_reaches_finish_with_no_denials_and_no_error():
    state, gov, reg = setup()
    port = ScriptedPort([make_follower()] * 8)
    await run_planner(state, gov, reg, port)
    assert denials(gov) == []
    assert gov.status is RunStatus.DONE
    assert ObsCode.ERROR not in {o.code for o in state.observations}
    assert {o.req_id for o in state.observations if o.req_id} == {"R1", "R2"}  # R3（手段なし）には run_check を出していない
    assert all(r.max_output_tokens == PLANNER_MAX_OUTPUT_TOKENS and r.thinking_budget == 0 for r in port.requests)


async def test_requirements_without_the_means_to_check_are_not_offered_as_run_check_targets():
    state, gov, reg = setup(no_submission_doc=True)
    view_routes = {r.req_id: r.routes for r in __import__("app.agent.planner", fromlist=["x"]).build_state_view(
        state, gov, 1, 8, gov.allowed_tools()).requirements}
    assert view_routes["R1"] == () and view_routes["R3"] == ()  # 字数は提出物の文書が要る／R3 は検査の種類が無い
    assert view_routes["R2"] != ()
    port = ScriptedPort([make_follower()] * 8)
    await run_planner(state, gov, reg, port)
    assert denials(gov) == [] and gov.status is RunStatus.DONE
    assert ObsCode.ERROR not in {o.code for o in state.observations}
    assert {o.req_id for o in state.observations if o.req_id} == {"R2"}


async def test_router_and_planner_both_end_done_under_the_same_conditions():
    for no_doc in (False, True):
        s1, g1, r1 = setup(no_submission_doc=no_doc)
        await run_router(s1, g1, r1)
        s2, g2, r2 = setup(no_submission_doc=no_doc)
        await run_planner(s2, g2, r2, ScriptedPort([make_follower()] * 8))
        assert g1.status is g2.status is RunStatus.DONE
        assert {o.req_id for o in s1.observations if o.req_id} == {o.req_id for o in s2.observations if o.req_id}
