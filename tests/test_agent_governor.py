"""governor.py: 許可リスト・拒否の policy_id と理由・上限・停止条件・フェーズ遷移（正常・境界・攻撃）。"""
import pytest

from app.agent.governor import PLANNER_MARK_CODES, Governor
from app.config import RUN_CAPS
from app.contracts import (
    AbortReason,
    Decision,
    DegradedReason,
    FetchKind,
    FunctionCall,
    Kind,
    LinkEntry,
    LinkRole,
    Observation,
    ObsCode,
    ObsOutcome,
    Phase,
    PolicyId,
    RunStatus,
    ToolName,
    TraceType,
    UnverifiableReason,
)
from tests.agent_support import AUTH_SENTENCE, LANG_SENTENCE, LEN_SENTENCE, FakeClock, SPEC_URL, SVC_HOST, make_world, raw
from app.contracts import CheckClass
from tests.factories import make_doc
from tests.fetch_fakes import SUB_URL

REQS = (
    raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),
    raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
    raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE),
)


def fc(name, **args):
    return FunctionCall(name=name, args=args)


def turn(gov: Governor, n: int = 1, max_turns: int = 8):
    gov.begin_turn(n, max_turns, gov.allowed_tools())


def denials(gov: Governor):
    return [(e.policy_id, e.reason_code) for e in gov.trace.events if e.decision is Decision.DENY]


def world(**kw):
    state, gov = make_world(reqs=REQS, **kw)
    turn(gov)
    return state, gov


def with_links(state, *hrefs, role=LinkRole.OTHER, in_scope=True):
    entries = tuple(
        LinkEntry(link_id=f"L{i}", href=h, anchor_text="リンク", role=role, in_scope=in_scope) for i, h in enumerate(hrefs, start=1)
    )
    state.add_doc(make_doc("D3", "リンクのある文書", links=entries))


# ---- 許可リスト ------------------------------------------------------------------------------------
def test_allowed_tools_follow_the_state_and_always_include_finish():
    state, gov = world()
    allowed = gov.allowed_tools()
    assert set(allowed) == {ToolName.HTTP_PROBE, ToolName.RUN_CHECK, ToolName.MARK_UNVERIFIABLE, ToolName.FINISH}
    assert ToolName.FETCH_LINK not in allowed  # リンクが無い
    with_links(state, f"https://{SVC_HOST}/fx/a")
    assert ToolName.FETCH_LINK in gov.allowed_tools()


def test_no_open_requirement_means_no_run_check_or_mark_but_finish_remains():
    state, gov = make_world(reqs=())
    assert gov.allowed_tools() == (ToolName.HTTP_PROBE, ToolName.FINISH)


def test_when_the_tool_budget_is_spent_only_finish_is_allowed():
    state, gov = world()
    gov.meter.budget.tool_calls = RUN_CAPS.tool_calls
    assert gov.allowed_tools() == (ToolName.FINISH,)


def test_probe_is_not_offered_once_its_own_cap_of_two_is_spent():
    state, gov = world()
    gov.meter.budget.charge_fetch(kind=FetchKind.HTTP_PROBE)
    assert ToolName.HTTP_PROBE in gov.allowed_tools()
    gov.meter.budget.charge_fetch(kind=FetchKind.HTTP_PROBE)
    assert ToolName.HTTP_PROBE not in gov.allowed_tools()


# ---- 攻撃: 乗っ取られた Planner の呼び出し -----------------------------------------------------------
ATTACKS = [
    ("存在しない関数", fc("delete_everything"), PolicyId.PHASE, "UNKNOWN_TOOL"),
    ("関数名に長い文字列", fc("x" * 64), PolicyId.PHASE, "UNKNOWN_TOOL"),
    ("今ターンの許可リスト外（リンクが無いのに fetch_link）", fc("fetch_link", link_id="L1", reason="r"), PolicyId.PHASE, "TOOL_NOT_ALLOWED"),
    ("link_id の代わりに URL", fc("http_probe", target="https://evil.invalid/", reason="r"), PolicyId.PHASE, "BAD_ARGS"),
    ("未知の引数", fc("run_check", checker="text_length", req_id="R1", url="https://evil.invalid/"), PolicyId.PHASE, "BAD_ARGS"),
    ("型違いの引数", fc("run_check", checker=["text_length"], req_id="R1"), PolicyId.PHASE, "BAD_ARGS"),
    ("存在しない要件", fc("run_check", checker="text_length", req_id="R99"), PolicyId.PHASE, "UNKNOWN_REQ"),
    ("存在しない link_id", fc("http_probe", target="L7", reason="r"), PolicyId.LINK, "UNKNOWN_LINK"),
    ("要件クラスと違う checker", fc("run_check", checker="cloud_run_signature", req_id="R1"), PolicyId.PHASE, "CLASS_MISMATCH"),
    ("検査の種類が無い要件", fc("run_check", checker="text_length", req_id="R3"), PolicyId.PHASE, "NOT_CHECKABLE"),
    ("コードだけが付ける理由コード", fc("mark_unverifiable", req_id="R1", reason_code="NO_EVIDENCE"), PolicyId.UNVERIF, "CODE_ONLY"),
    ("予算切れを名乗って検査を省く", fc("mark_unverifiable", req_id="R1", reason_code="BUDGET"), PolicyId.UNVERIF, "CODE_ONLY"),
    ("前提の無い NEEDS_AUTH", fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_AUTH"), PolicyId.UNVERIF, "NO_PREMISE"),
    ("前提の無い NEEDS_JS", fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_JS"), PolicyId.UNVERIF, "NO_PREMISE"),
    ("検査を省いて認証壁の要件を確認不能にする", fc("mark_unverifiable", req_id="R2", reason_code="HUMAN_ONLY"), PolicyId.UNVERIF, "CHECK_FIRST"),
    ("finish が早すぎる", fc("finish"), PolicyId.MINTURN, "OPEN_REQUIREMENTS"),
]


@pytest.mark.parametrize("label,call,policy,reason", ATTACKS, ids=[a[0] for a in ATTACKS])
def test_hijacked_calls_are_denied_with_policy_and_reason_and_nothing_is_charged(label, call, policy, reason):
    state, gov = world()
    adm = gov.admit(call)
    assert not adm.allowed and (adm.policy, adm.reason) == (policy, reason)
    assert denials(gov) == [(policy, reason)]  # トレースに policy_id と理由コードが残る
    assert gov.meter.budget.tool_calls == 0 and state.req_calls == {} and gov.denied == 1


def test_denied_event_never_contains_the_model_supplied_name_or_url():
    state, gov = world()
    gov.admit(fc("exfiltrate_to_https://evil.invalid/steal"))
    dumped = "".join(e.model_dump_json() for e in gov.trace.events)
    assert "evil" not in dumped and "exfiltrate" not in dumped


def test_a_valid_call_is_allowed_charged_and_traced():
    state, gov = world()
    adm = gov.admit(fc("run_check", checker="text_length", req_id="R1"))
    assert adm.allowed and adm.call.name is ToolName.RUN_CHECK
    assert gov.meter.budget.tool_calls == 1 and state.req_calls == {"R1": 1}
    types = [e.type for e in gov.trace.events]
    assert types == [TraceType.TOOL_REQUEST, TraceType.POLICY_DECISION]
    assert gov.trace.events[1].decision is Decision.ALLOW


# ---- 重複・ループ ---------------------------------------------------------------------------------
def test_identical_call_is_denied_as_duplicate():
    state, gov = world()
    assert gov.admit(fc("run_check", checker="text_length", req_id="R1")).allowed
    adm = gov.admit(fc("run_check", checker="text_length", req_id="R1"))
    assert (adm.policy, adm.reason) == (PolicyId.DUP, "DUPLICATE_CALL")


def test_run_check_may_be_repeated_only_after_new_evidence_arrived():
    state, gov = world()
    assert gov.admit(fc("run_check", checker="auth_wall", req_id="R2")).allowed  # probe の前に呼んで不確定になる想定
    state.observations.append(probe_obs(ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, target="SUBMISSION_URL", obs_id="O1"))  # その結果（自分の1件）
    assert gov.admit(fc("run_check", checker="auth_wall", req_id="R2")).reason == "DUPLICATE_CALL"  # 新しい証拠なしの繰り返し
    state.observations.append(probe_obs(obs_id="O2"))  # 別の観測（probe の結果）が増えた
    assert gov.admit(fc("run_check", checker="auth_wall", req_id="R2")).allowed  # 新しい証拠のもとでのやり直し


def test_other_tools_are_never_repeatable_even_after_new_observations():
    state, gov = world()
    assert gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="a")).allowed
    state.observations += [probe_obs(obs_id="O1"), probe_obs(obs_id="O2"), probe_obs(obs_id="O3")]
    assert gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="b")).reason == "DUPLICATE_CALL"


def test_rewording_the_reason_does_not_evade_the_duplicate_check():
    state, gov = world()
    assert gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="最初の理由")).allowed
    adm = gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="言い換えた理由"))
    assert (adm.policy, adm.reason) == (PolicyId.DUP, "DUPLICATE_CALL")


def test_a_loop_of_denied_calls_stops_the_run_as_degraded_denial_streak():
    state, gov = world()
    for _ in range(RUN_CAPS.consecutive_denials_stop):
        assert not gov.admit(fc("nope")).allowed
    assert gov.check_stop()
    assert (gov.status, gov.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.DENIAL_STREAK)


def test_an_allowed_call_resets_the_denial_streak():
    state, gov = world()
    gov.admit(fc("nope"))
    gov.admit(fc("nope"))
    assert gov.admit(fc("run_check", checker="text_length", req_id="R1")).allowed
    assert gov.denial_streak == 0
    gov.admit(fc("nope"))
    gov.admit(fc("nope"))
    assert not gov.check_stop()  # 連続は2回まで。3回連続ではない


def test_planner_that_answers_without_calling_anything_counts_as_a_denial():
    state, gov = world()
    for _ in range(RUN_CAPS.consecutive_denials_stop):
        gov.deny_no_call()
    assert gov.check_stop() and gov.degraded_reason is DegradedReason.DENIAL_STREAK
    assert ("P-PHASE-02", "NO_CALL") in [(str(p), r) for p, r in denials(gov)]


# ---- 上限 ------------------------------------------------------------------------------------------
def test_per_requirement_cap_of_three_counts_every_call_for_the_requirement():
    state, gov = world()
    for code in ("HUMAN_ONLY", "FUTURE", "OUT_OF_SCOPE"):  # R3 は検査の種類が無い要件（印は自由に付けられる）
        assert gov.admit(fc("mark_unverifiable", req_id="R3", reason_code=code)).allowed
    adm = gov.admit(fc("mark_unverifiable", req_id="R3", reason_code="NOT_PUBLIC"))
    assert (adm.policy, adm.reason) == (PolicyId.BUDGET_CALLS, "REQ_CAP")
    assert state.calls_used("R3") == RUN_CAPS.tool_calls_per_requirement


def test_total_tool_call_cap_denies_even_with_a_stale_allowed_list():
    state, gov = world()
    gov.meter.budget.tool_calls = RUN_CAPS.tool_calls  # allowed は turn 開始時に決めたまま
    adm = gov.admit(fc("run_check", checker="text_length", req_id="R1"))
    assert (adm.policy, adm.reason) == (PolicyId.BUDGET_CALLS, "TOOL_CAP")


def test_the_16th_call_is_allowed_and_the_17th_is_not():
    state, gov = world()
    for i in range(RUN_CAPS.tool_calls - 1):
        gov.meter.budget.charge_tool_call()
    assert gov.admit(fc("run_check", checker="text_length", req_id="R1")).allowed
    assert not gov.admit(fc("run_check", checker="auth_wall", req_id="R2")).allowed


def test_probe_cap_is_enforced_by_kind():
    state, gov = world()
    gov.meter.budget.charge_fetch(kind=FetchKind.HTTP_PROBE)
    gov.meter.budget.charge_fetch(kind=FetchKind.HTTP_PROBE)
    turn(gov)  # 次のターンの許可リストから外れる
    adm = gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="r"))
    assert adm.reason == "TOOL_NOT_ALLOWED"  # 許可リストから外れている
    gov.begin_turn(2, 8, (ToolName.HTTP_PROBE, ToolName.FINISH))  # 乗っ取りで許可リストを偽装しても
    adm = gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.BUDGET_CALLS, "FETCH_CAP")


def test_third_party_origin_cap_is_enforced():
    state, gov = world()
    with_links(state, "https://a.example.invalid/x", "https://b.example.invalid/x", "https://c.example.invalid/x",
               "https://d.example.invalid/x", "https://e.example.invalid/x")
    turn(gov)
    for host in "abcd":
        gov.meter.budget.charge_fetch(gov.third_party_origin(f"https://{host}.example.invalid/x"))  # 種別の枠には数えない
    assert len(gov.meter.budget.third_party_origins) == RUN_CAPS.third_party_origins == 4
    gov.begin_turn(1, 8, (ToolName.FETCH_LINK, ToolName.FINISH))
    adm = gov.admit(fc("fetch_link", link_id="L5", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.BUDGET_CALLS, "ORIGIN_CAP")
    assert gov.admit(fc("fetch_link", link_id="L1", reason="r")).allowed  # 既に数えた origin は通る
    assert all("example" not in o for o in gov.meter.budget.third_party_origins)  # ホスト名は別名にする


def test_own_hosts_of_the_preset_are_not_third_party():
    state, gov = world()
    assert gov.third_party_origin(SUB_URL) is None and gov.third_party_origin(SPEC_URL) is None
    assert gov.third_party_origin("https://elsewhere.example.invalid/") is not None


# ---- リンク -----------------------------------------------------------------------------------------
def test_out_of_scope_and_login_links_are_denied():
    state, gov = world()
    with_links(state, "https://other.example.invalid/x")
    state.links["L1"] = type(state.links["L1"])(state.links["L1"].entry.model_copy(update={"in_scope": False}), "D3", "L1")
    with_links_state = state
    turn(gov)
    gov.begin_turn(1, 8, (ToolName.FETCH_LINK, ToolName.HTTP_PROBE, ToolName.FINISH))
    adm = gov.admit(fc("fetch_link", link_id="L1", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.SCOPE, "OUT_OF_SCOPE")
    adm = gov.admit(fc("http_probe", target="L1", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.SCOPE, "OUT_OF_SCOPE")
    state2, gov2 = world()
    with_links(state2, f"https://{SVC_HOST}/fx/login", role=LinkRole.LOGIN)
    gov2.begin_turn(1, 8, (ToolName.FETCH_LINK, ToolName.FINISH))
    adm = gov2.admit(fc("fetch_link", link_id="L1", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.LINK, "LOGIN_LINK")
    assert with_links_state is state


def test_probe_without_submission_url_is_denied():
    from app.contracts import Preset

    from tests.agent_support import PRESET

    no_sub = Preset(preset_id="sample_defect", label_ja="x", kind="fixture_defect", spec_seed_urls=PRESET.spec_seed_urls,  # type: ignore[arg-type]
                    submission_url=None, allowed_prefixes=PRESET.allowed_prefixes)
    state, gov = make_world(reqs=REQS, preset=no_sub)
    gov.begin_turn(1, 8, (ToolName.HTTP_PROBE, ToolName.FINISH))
    adm = gov.admit(fc("http_probe", target="SUBMISSION_URL", reason="r"))
    assert (adm.policy, adm.reason) == (PolicyId.SCOPE, "NO_SUBMISSION_URL")


# ---- P-UNVERIF-01 / P-MINTURN-01 -----------------------------------------------------------------
def probe_obs(code=ObsCode.AUTH_WALL, outcome=ObsOutcome.FAIL, target="SUBMISSION_URL", obs_id="O1"):
    return Observation(obs_id=obs_id, tool=ToolName.HTTP_PROBE, code=code, outcome=outcome, strong=outcome is not ObsOutcome.INCONCLUSIVE,
                       facts={"target": target, "access": "login_redirect"})


def test_needs_auth_is_allowed_only_with_an_auth_wall_observation_on_the_submission_url():
    state, gov = world()
    state.observations.append(probe_obs())
    adm = gov.admit(fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_AUTH"))
    assert adm.allowed and adm.premise_obs_id == "O1"


def test_a_probe_of_some_other_target_is_not_a_premise():
    state, gov = world()
    state.observations.append(probe_obs(target="L1"))
    adm = gov.admit(fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_AUTH"))
    assert (adm.policy, adm.reason) == (PolicyId.UNVERIF, "NO_PREMISE")


def test_needs_js_needs_a_spa_shell_observation():
    state, gov = world()
    state.observations.append(probe_obs())  # 認証壁は NEEDS_JS の前提ではない
    assert gov.admit(fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_JS")).reason == "NO_PREMISE"
    state.observations.append(probe_obs(ObsCode.SPA_SHELL, ObsOutcome.INCONCLUSIVE, obs_id="O2"))
    assert gov.admit(fc("mark_unverifiable", req_id="R3", reason_code="NEEDS_JS")).allowed


def test_marks_on_speculative_or_already_decided_requirements_are_denied():
    state, gov = make_world(reqs=(raw(LEN_SENTENCE, Kind.SPECULATIVE), REQS[1]))
    turn(gov)
    assert gov.admit(fc("mark_unverifiable", req_id="R1", reason_code="HUMAN_ONLY")).reason == "SPECULATIVE"
    state.observations.append(
        Observation(obs_id="O1", tool=ToolName.RUN_CHECK, checker="auth_wall", req_id="R2", code=ObsCode.AUTH_WALL,  # type: ignore[arg-type]
                    outcome=ObsOutcome.FAIL, strong=True)
    )
    assert gov.admit(fc("mark_unverifiable", req_id="R2", reason_code="HUMAN_ONLY")).reason == "ALREADY_DECIDED"


def test_a_checkable_requirement_may_be_marked_only_after_its_own_check_was_inconclusive():
    state, gov = world()
    assert gov.admit(fc("mark_unverifiable", req_id="R1", reason_code="HUMAN_ONLY")).reason == "CHECK_FIRST"
    state.observations.append(
        Observation(obs_id="O1", tool=ToolName.RUN_CHECK, checker="text_length", req_id="R1", code=ObsCode.LIMIT_UNDECIDABLE,  # type: ignore[arg-type]
                    outcome=ObsOutcome.INCONCLUSIVE)
    )
    assert gov.admit(fc("mark_unverifiable", req_id="R1", reason_code="HUMAN_ONLY")).allowed  # 検査は走った（不確定）


def test_planner_may_only_use_the_documented_mark_codes():
    assert PLANNER_MARK_CODES == {UnverifiableReason.NEEDS_AUTH, UnverifiableReason.NEEDS_JS, UnverifiableReason.HUMAN_ONLY,
                                  UnverifiableReason.FUTURE, UnverifiableReason.OUT_OF_SCOPE, UnverifiableReason.NOT_PUBLIC}


def test_finish_is_refused_while_a_checkable_requirement_is_untouched():
    state, gov = world()
    assert gov.pending_checks() == ["R1", "R2"]
    assert gov.admit(fc("finish")).reason == "OPEN_REQUIREMENTS"
    gov.admit(fc("run_check", checker="text_length", req_id="R1"))
    gov.admit(fc("run_check", checker="auth_wall", req_id="R2"))
    assert gov.pending_checks() == []
    assert gov.admit(fc("finish")).allowed


def test_finish_is_allowed_on_the_last_turn_and_when_the_budget_is_spent():
    state, gov = world()
    gov.begin_turn(8, 8, gov.allowed_tools())
    assert gov.admit(fc("finish")).allowed
    state2, gov2 = world()
    gov2.meter.budget.tokens_in = RUN_CAPS.tokens_in
    turn(gov2)
    assert gov2.admit(fc("finish")).allowed


# ---- 停止条件 ---------------------------------------------------------------------------------------
def test_kill_switch_aborts_denies_everything_and_leaves_a_p_kill_event():
    state, gov = world(kill=True)
    assert gov.check_stop()
    assert (gov.status, gov.aborted_reason) == (RunStatus.ABORTED, AbortReason.KILL)
    assert (PolicyId.KILL, "KILLED") in denials(gov)
    assert not gov.admit(fc("run_check", checker="text_length", req_id="R1")).allowed
    assert gov.meter.budget.tool_calls == 0


def test_kill_switch_can_flip_during_the_run():
    flag = {"on": False}
    state, gov = world(kill=lambda: flag["on"])
    assert gov.admit(fc("run_check", checker="text_length", req_id="R1")).allowed
    flag["on"] = True
    assert not gov.admit(fc("run_check", checker="auth_wall", req_id="R2")).allowed
    assert gov.status is RunStatus.ABORTED and gov.aborted_reason is AbortReason.KILL


def test_wall_clock_overrun_aborts_with_wall_clock():
    clock = FakeClock()
    state, gov = world(clock=clock)
    assert not gov.check_stop()
    clock.advance(RUN_CAPS.wall_clock_s + 1)
    assert gov.check_stop() and gov.aborted_reason is AbortReason.WALL_CLOCK


def test_abort_wins_over_a_later_degrade_and_the_first_degrade_reason_is_kept():
    state, gov = world()
    gov.degrade(DegradedReason.MODEL_FAILURE)
    gov.degrade(DegradedReason.BUDGET)
    assert gov.degraded_reason is DegradedReason.MODEL_FAILURE
    gov.abort(AbortReason.WALL_CLOCK)
    gov.degrade(DegradedReason.BUDGET)
    assert gov.status is RunStatus.ABORTED and gov.degraded_reason is DegradedReason.MODEL_FAILURE


def test_exhausted_budget_degrades_with_budget_reason():
    state, gov = world()
    gov.meter.budget.tokens_out = RUN_CAPS.tokens_out
    assert gov.check_stop() and gov.degraded_reason is DegradedReason.BUDGET


def test_nothing_is_admitted_after_the_run_has_stopped():
    state, gov = world()
    gov.degrade(DegradedReason.BUDGET)
    adm = gov.admit(fc("finish"))
    assert not adm.allowed and gov.meter.budget.tool_calls == 0


# ---- モデル呼び出しの予約 -------------------------------------------------------------------------------
def test_reserve_model_denies_with_the_right_policy():
    from app.contracts import ModelPurpose

    state, gov = world()
    assert gov.reserve_model(ModelPurpose.PLANNER, RUN_CAPS.tokens_in + 1, 10) is None
    assert (PolicyId.BUDGET_TOKENS, "TOKENS") in denials(gov)
    caps = RUN_CAPS.model_copy(update={"model_calls_reader": 1, "model_calls_planner": 1, "model_calls_spare": 0})
    state, gov = make_world(reqs=REQS, caps=caps)
    assert gov.reserve_model(ModelPurpose.PLANNER, 1, 1) is not None
    assert gov.reserve_model(ModelPurpose.PLANNER, 1, 1) is None
    assert (PolicyId.BUDGET_CALLS, "MODEL_CALLS") in denials(gov)


def test_reserve_model_aborts_on_kill_and_on_wall_clock():
    from app.contracts import ModelPurpose

    state, gov = world(kill=True)
    assert gov.reserve_model(ModelPurpose.READER, 1, 1) is None and gov.aborted_reason is AbortReason.KILL
    clock = FakeClock()
    state, gov = world(clock=clock)
    clock.advance(RUN_CAPS.wall_clock_s)
    assert gov.reserve_model(ModelPurpose.READER, 1, 1) is None and gov.aborted_reason is AbortReason.WALL_CLOCK


# ---- フェーズ ---------------------------------------------------------------------------------------
def test_phase_transitions_follow_the_state_machine():
    state, gov = make_world()
    gov.phase = Phase.ADMIT
    for p in (Phase.ACQUIRE, Phase.READ, Phase.INSPECT, Phase.ADJUDICATE, Phase.REPORT, Phase.DONE):
        gov.enter(p)
    assert [e.name for e in gov.trace.events if e.type is TraceType.PHASE_ENTER] == [
        "ACQUIRE", "READ", "INSPECT", "ADJUDICATE", "REPORT", "DONE"]


@pytest.mark.parametrize("frm,to", [(Phase.ADMIT, Phase.READ), (Phase.READ, Phase.ADJUDICATE), (Phase.INSPECT, Phase.READ),
                                    (Phase.DONE, Phase.ACQUIRE), (Phase.ACQUIRE, Phase.ACQUIRE)])
def test_illegal_transitions_raise(frm, to):
    state, gov = make_world()
    gov.phase = frm
    with pytest.raises(ValueError):
        gov.enter(to)


def test_every_deny_event_in_a_noisy_session_carries_policy_and_reason():
    state, gov = world()
    for c in (fc("x"), fc("run_check", checker="text_length", req_id="R9"), fc("finish"), fc("http_probe", target="L5", reason="r")):
        gov.admit(c)
        gov.denial_streak = 0
    ev = [e for e in gov.trace.events if e.decision is Decision.DENY]
    assert len(ev) == gov.denied == 4 and all(e.policy_id and e.reason_code for e in ev)
