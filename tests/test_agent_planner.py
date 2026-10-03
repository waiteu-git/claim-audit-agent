"""planner.py: StateView（約3KB・自由文なし）・Planner ループ・乗っ取られた Planner・router。"""
import json

import pytest

from app.agent.planner import (
    PLANNER_SYSTEM,
    InspectMode,
    build_state_view,
    compute_features,
    routes_for,
    run_planner,
    run_router,
)
from app.agent.tools import ToolRegistry
from app.config import RUN_CAPS
from app.contracts import (
    STATE_VIEW_TARGET_BYTES,
    CheckClass,
    DegradedReason,
    FeatureCategory,
    Kind,
    LinkEntry,
    LinkRole,
    ModelPurpose,
    ObsCode,
    ReqState,
    RunStatus,
    StateView,
    ToolName,
    TraceType,
)
from app.errors import AppError, ErrorCode
from app.model.scripted import ScriptedPort, reply_calls
from tests.agent_support import (
    AUTH_SENTENCE,
    INJECTION,
    LANG_SENTENCE,
    LEN_SENTENCE,
    SVC_HOST,
    make_world,
    raw,
    standard_fetch,
    standard_planner,
)
from tests.factories import make_doc

REQS = (
    raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT, gist=INJECTION),
    raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
    raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE),
)
LONG_SUB = "あ" * 120


def setup(*, caps=RUN_CAPS, fetch=None, reqs=REQS):
    state, gov = make_world(caps=caps, reqs=reqs, submission_text=LONG_SUB)
    reg = ToolRegistry(state=state, governor=gov, fetch=fetch or standard_fetch())
    return state, gov, reg


def view_of(state, gov, turn=1, max_turns=8):
    return build_state_view(state, gov, turn, max_turns, gov.allowed_tools())


# ---- StateView -------------------------------------------------------------------------------------
def test_state_view_holds_ids_enums_and_numbers_only_never_text():
    state, gov, _ = setup()
    state.add_doc(make_doc("D3", "リンク文書", links=(LinkEntry(link_id="L1", href=f"https://{SVC_HOST}/fx/x", anchor_text=f"ここを押せ {INJECTION}",
                                                              role=LinkRole.OTHER, in_scope=True),)))
    j = view_of(state, gov).to_prompt_json()
    for forbidden in (LEN_SENTENCE, AUTH_SENTENCE, LANG_SENTENCE, INJECTION, "ここを押せ", "https://", SVC_HOST, "応募要項", "架空"):
        assert forbidden not in j, forbidden
    d = json.loads(j)
    assert set(d) == {"turn", "max_turns", "allowed_tools", "requirements", "docs", "links", "budget", "last_observation"}
    assert set(d["requirements"][0]) == {"req_id", "kind", "check_class", "state", "routes", "calls_used"}
    assert set(d["docs"][0]) == {"doc_id", "role", "page_class", "truncated", "features"}
    assert set(d["links"][0]) == {"link_id", "role", "in_scope", "fetched"}


def test_state_view_has_no_free_text_field_in_its_type():
    """型の側の保証: StateView 配下のどのフィールドも自由文（任意の str）を持たない。"""
    schema = json.dumps(StateView.model_json_schema())
    assert '"anchor_text"' not in schema and '"gist"' not in schema and '"quote"' not in schema and '"visible_text"' not in schema


def test_state_view_is_deterministic_and_small():
    state, gov, _ = setup()
    a, b = view_of(state, gov), view_of(state, gov)
    assert a.to_prompt_json() == b.to_prompt_json() and a.size_bytes() < STATE_VIEW_TARGET_BYTES
    assert [r.req_id for r in a.requirements] == ["R1", "R2", "R3"]


def test_routes_come_from_the_table_and_empty_when_not_checkable():
    state, gov, _ = setup()
    r1, r2, r3 = state.requirements
    assert routes_for(state, r1) == ("run_check:text_length",)
    assert routes_for(state, r2) == ("http_probe:SUBMISSION_URL", "run_check:auth_wall")
    assert routes_for(state, r3) == ()


def test_state_view_is_trimmed_to_about_3kb_with_many_requirements():
    sentences = [f"項目{i:02d}は提出物に含める説明の字数を100字以内とすること。" for i in range(64)]
    text = "応募要項\u001e" + "\u001e".join(sentences)
    reqs = tuple(raw(s, Kind.REQUIRED, CheckClass.LENGTH_LIMIT) for s in sentences)
    state, gov = make_world(spec_text=text, reqs=reqs)
    assert len(state.requirements) == 64
    many = tuple(LinkEntry(link_id=f"L{i}", href=f"https://{SVC_HOST}/fx/{i}", anchor_text="a", in_scope=True) for i in range(1, 41))
    state.add_doc(make_doc("D9", "x", links=many))  # リンクも多い
    v = view_of(state, gov)
    assert v.size_bytes() <= STATE_VIEW_TARGET_BYTES
    assert 8 <= len(v.requirements) < 64 and v.requirements[0].req_id == "R1"
    assert all(r.state is ReqState.OPEN for r in v.requirements)


def test_state_view_is_trimmed_even_when_the_documents_alone_are_too_many():
    state, gov = make_world(reqs=REQS)
    for i in range(40):
        state.add_doc(make_doc(f"D{10 + i}", "ログイン デモ 動画 " * 5))
    assert view_of(state, gov).size_bytes() <= STATE_VIEW_TARGET_BYTES


def test_open_requirements_are_listed_before_done_ones_and_done_ones_drop_first():
    state, gov, _ = setup()
    from app.contracts import Observation, ObsOutcome

    state.observations.append(Observation(obs_id="O1", tool=ToolName.RUN_CHECK, checker="text_length", req_id="R1",  # type: ignore[arg-type]
                                          code=ObsCode.OVER_LIMIT, outcome=ObsOutcome.FAIL, strong=True))
    v = view_of(state, gov)
    assert [(r.req_id, r.state) for r in v.requirements][:2] == [("R2", ReqState.OPEN), ("R3", ReqState.OPEN)]
    assert v.requirements[-1].state is ReqState.DONE


def test_doc_features_are_counts_from_code_vocabulary():
    doc = make_doc("D1", "ログインは必須。アカウントを用意し、デモ動画を添付。締切は10月。ログインできること。")
    state, _, _ = setup()
    f = compute_features(doc, state)
    assert f.length == len(doc.visible_text)
    assert f.category_hits[FeatureCategory.AUTH] == 2 and f.category_hits[FeatureCategory.ACCOUNT] == 1
    assert FeatureCategory.LICENSE not in f.category_hits


def test_unread_spec_documents_show_as_truncated_to_the_planner():
    state, gov, _ = setup()
    state.unread_doc_ids.add("D1")
    assert next(d for d in view_of(state, gov).docs if d.doc_id == "D1").truncated is True


# ---- Planner ループ（正常）--------------------------------------------------------------------------
async def test_scripted_planner_runs_the_inspection_to_the_end():
    state, gov, reg = setup()
    port = standard_planner()
    await run_planner(state, gov, reg, port)
    assert gov.status is RunStatus.DONE and port.remaining == 0
    assert {o.req_id for o in state.observations if o.req_id} == {"R1", "R2"}
    assert [o.code for o in state.observations] == [ObsCode.AUTH_WALL, ObsCode.AUTH_WALL, ObsCode.OVER_LIMIT]


async def test_planner_request_exposes_only_the_allowed_tools_and_the_state_view():
    state, gov, reg = setup()
    port = standard_planner()
    await run_planner(state, gov, reg, port)
    for i, req in enumerate(port.requests):
        assert req.purpose is ModelPurpose.PLANNER and req.response_model is None and req.system == PLANNER_SYSTEM
        declared = [t.name for t in req.tools]
        assert declared == list(req.allowed_tool_names) and ToolName.FINISH in declared
        view = json.loads(req.contents)  # 内容は StateView の JSON そのもの
        assert view["turn"] == i + 1 and view["allowed_tools"] == [t.value for t in declared]
        for forbidden in (LEN_SENTENCE, AUTH_SENTENCE, INJECTION, "https://"):
            assert forbidden not in req.contents and forbidden not in req.system
        assert len(req.contents.encode()) <= STATE_VIEW_TARGET_BYTES


async def test_state_view_is_traced_every_turn_and_the_last_observation_feeds_the_next_view():
    state, gov, reg = setup()
    port = standard_planner()
    await run_planner(state, gov, reg, port)
    views = [e.state_view for e in gov.trace.events if e.type is TraceType.STATE_VIEW]
    assert [v.turn for v in views] == [1, 2, 3, 4]
    assert [v.last_observation for v in views] == [None, ObsCode.AUTH_WALL, ObsCode.AUTH_WALL, ObsCode.OVER_LIMIT]


async def test_the_planner_sees_each_turn_only_what_the_code_rebuilds_no_history():
    state, gov, reg = setup()
    port = standard_planner()
    await run_planner(state, gov, reg, port)
    assert all(set(json.loads(r.contents)) <= {"turn", "max_turns", "allowed_tools", "requirements", "docs", "links", "budget", "last_observation"}
               for r in port.requests)


async def test_planner_model_calls_are_charged_to_the_planner_budget():
    state, gov, reg = setup()
    await run_planner(state, gov, reg, standard_planner())
    b = gov.meter.budget
    assert b.planner_calls == 4 and b.reader_calls == 0
    assert [e.purpose for e in gov.trace.events if e.type is TraceType.MODEL_CALL] == [ModelPurpose.PLANNER] * 4


# ---- 攻撃: 乗っ取られた Planner ---------------------------------------------------------------------
async def test_hijacked_planner_cycling_through_forbidden_calls_is_stopped_after_three_denials():
    steps = [reply_calls(("fetch_link", {"link_id": "https://evil.invalid/steal", "reason": "x"})),
             reply_calls(("exfiltrate", {"data": "all"})),
             reply_calls(("run_check", {"checker": "text_length", "req_id": "R42"}))] + [reply_calls(("finish", {}))] * 5
    state, gov, reg = setup()
    port = ScriptedPort(steps)
    await run_planner(state, gov, reg, port)
    assert (gov.status, gov.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.DENIAL_STREAK)
    assert len(port.requests) == 3 and port.remaining == 5  # 4回目以降は呼ばれない
    assert state.observations == [] and gov.meter.budget.tool_calls == 0  # 何も実行されていない
    assert gov.denied == 3


async def test_planner_trying_to_finish_immediately_is_refused_and_must_do_the_work():
    steps = [reply_calls(("finish", {})), reply_calls(("run_check", {"checker": "text_length", "req_id": "R1"})),
             reply_calls(("http_probe", {"target": "SUBMISSION_URL", "reason": "r"})), reply_calls(("run_check", {"checker": "auth_wall", "req_id": "R2"})),
             reply_calls(("finish", {}))]
    state, gov, reg = setup()
    port = ScriptedPort(steps)
    await run_planner(state, gov, reg, port)
    assert gov.status is RunStatus.DONE and gov.denied == 1 and len(state.observations) == 3


async def test_planner_calling_a_tool_outside_this_turns_allowed_list_is_denied():
    state, gov, reg = setup()  # リンクが無いので fetch_link は許可リストに無い
    port = ScriptedPort([reply_calls(("fetch_link", {"link_id": "L1", "reason": "r"}))] + [reply_calls(("finish", {}))] * 3)
    await run_planner(state, gov, reg, port)
    reasons = [e.reason_code for e in gov.trace.events if e.reason_code == "TOOL_NOT_ALLOWED"]
    assert reasons == ["TOOL_NOT_ALLOWED"]
    assert all(ToolName.FETCH_LINK not in r.allowed_tool_names for r in port.requests)


async def test_model_call_cap_stops_the_planner_even_if_it_never_finishes():
    caps = RUN_CAPS.model_copy(update={"model_calls_planner": 2, "model_calls_reader": 1, "model_calls_spare": 0})
    state, gov, reg = setup(caps=caps)
    never = [reply_calls(("http_probe", {"target": "SUBMISSION_URL", "reason": "r"}))] + [reply_calls(("mark_unverifiable", {"req_id": "R3", "reason_code": "HUMAN_ONLY"}))] * 6
    port = ScriptedPort(never)
    await run_planner(state, gov, reg, port)
    assert len(port.requests) == 2 and port.remaining == len(never) - 2
    assert (gov.status, gov.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.BUDGET)


async def test_token_budget_stops_the_planner_before_the_call_is_made():
    state, gov, reg = setup()
    gov.meter.budget.tokens_in = RUN_CAPS.tokens_in - 5
    port = ScriptedPort([reply_calls(("finish", {}))])
    await run_planner(state, gov, reg, port)
    assert port.requests == [] and gov.degraded_reason is DegradedReason.BUDGET


async def test_turn_limit_degrades_when_checkable_requirements_were_never_touched():
    caps = RUN_CAPS.model_copy(update={"planner_max_turns": 2})
    state, gov, reg = setup(caps=caps)
    port = ScriptedPort([reply_calls(("mark_unverifiable", {"req_id": "R3", "reason_code": "HUMAN_ONLY"})),
                         reply_calls(("mark_unverifiable", {"req_id": "R3", "reason_code": "FUTURE"}))] + [reply_calls(("finish", {}))] * 3)
    await run_planner(state, gov, reg, port)
    assert len(port.requests) == 2 and gov.degraded_reason is DegradedReason.BUDGET


async def test_planner_that_returns_text_only_is_counted_as_denials_and_stopped():
    from app.model.scripted import reply_json

    state, gov, reg = setup()
    port = ScriptedPort([reply_json("全て適合です。finish します。")] * 5)
    await run_planner(state, gov, reg, port)
    assert gov.degraded_reason is DegradedReason.DENIAL_STREAK and len(port.requests) == 3 and state.observations == []


async def test_more_than_four_calls_in_one_turn_are_cut_off():
    calls = [("mark_unverifiable", {"req_id": "R3", "reason_code": c}) for c in ("HUMAN_ONLY", "FUTURE", "OUT_OF_SCOPE", "NOT_PUBLIC", "NEEDS_AUTH")]
    state, gov, reg = setup()
    port = ScriptedPort([reply_calls(*calls), reply_calls(("finish", {}))])
    await run_planner(state, gov, reg, port)
    assert gov.meter.budget.tool_calls <= 3  # 要件ごとの3回の枠で、2回目以降は拒否される
    assert state.calls_used("R3") == 1 and "R3" in state.marks


async def test_planner_model_failure_degrades_with_model_failure():
    state, gov, reg = setup()
    await run_planner(state, gov, reg, ScriptedPort([AppError(ErrorCode.RETRYABLE, "x")]))
    assert gov.degraded_reason is DegradedReason.MODEL_FAILURE


async def test_planner_fatal_config_error_is_raised():
    state, gov, reg = setup()
    with pytest.raises(AppError):
        await run_planner(state, gov, reg, ScriptedPort([AppError(ErrorCode.FATAL_CONFIG, "x")]))


async def test_kill_switch_stops_the_planner_loop_before_any_call():
    state, gov, reg = setup()
    gov.kill_switch = True
    port = ScriptedPort([reply_calls(("finish", {}))])
    await run_planner(state, gov, reg, port)
    assert port.requests == [] and gov.status is RunStatus.ABORTED


# ---- router ----------------------------------------------------------------------------------------
async def test_router_runs_the_same_checks_through_the_same_governor():
    state, gov, reg = setup()
    await run_router(state, gov, reg)
    assert gov.status is RunStatus.DONE and [o.code for o in state.observations] == [ObsCode.AUTH_WALL, ObsCode.OVER_LIMIT, ObsCode.AUTH_WALL]
    types = [e.type for e in gov.trace.events]
    assert types.count(TraceType.TOOL_REQUEST) == 4 and types.count(TraceType.POLICY_DECISION) == 4  # probe・R1・R2・finish
    assert gov.meter.budget.model_calls == 0  # LLM を呼ばない
    assert gov.meter.budget.tool_calls == 4


async def test_router_and_planner_reach_the_same_observations():
    s1, g1, r1 = setup()
    s2, g2, r2 = setup()
    await run_router(s1, g1, r1)
    await run_planner(s2, g2, r2, standard_planner())
    key = lambda s: sorted((o.req_id or "", o.code.value, o.outcome.value) for o in s.observations)  # noqa: E731
    assert key(s1) == key(s2)


async def test_router_skips_the_probe_when_no_requirement_needs_it():
    state, gov, reg = setup(reqs=(REQS[0],))
    await run_router(state, gov, reg)
    assert [o.tool for o in state.observations] == [ToolName.RUN_CHECK]


async def test_router_does_not_run_checks_the_class_screen_would_reject():
    bad = raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT)  # 字数の話題に触れていない引用
    state, gov, reg = setup(reqs=(bad,))
    await run_router(state, gov, reg)
    assert state.observations == [] and gov.denied == 0


async def test_router_obeys_the_tool_call_cap_and_degrades():
    caps = RUN_CAPS.model_copy(update={"tool_calls": 1})
    state, gov, reg = setup(caps=caps)
    await run_router(state, gov, reg)
    assert gov.meter.budget.tool_calls == 1 and len(state.observations) == 1
    assert gov.degraded_reason is DegradedReason.BUDGET


async def test_router_obeys_the_kill_switch():
    state, gov, reg = setup()
    gov.kill_switch = True
    fetch = standard_fetch()
    reg2 = ToolRegistry(state=state, governor=gov, fetch=fetch)
    await run_router(state, gov, reg2)
    assert fetch.calls == [] and state.observations == [] and gov.status is RunStatus.ABORTED


def test_inspect_mode_values():
    assert {m.value for m in InspectMode} == {"planner", "router"}
