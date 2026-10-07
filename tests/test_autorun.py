"""AUTORUN: 計画（純関数）・実行（直接／Governor 経由）・Reader の提案の裏取り・router と Planner の結論が同じこと。
文章はすべて合成した架空のもの。"""
import pytest

from app import contracts as C
from app.agent.autorun_phase import AUTORUN_RESERVE_CALLS
from app.agent.planner import InspectMode
from app.checks.autorun import StepKind, autorun, confirm_page_class, plan_autorun
from app.checks.registry import CheckContext
from app.config import RUN_CAPS
from app.contracts import CheckClass, DocRole, Kind, PageClass, TraceType
from app.fixtures import gen
from app.fixtures.eval import RulePlanner, run_variant
from app.quotes import DocIndex, QuoteChecker
from tests.agent_support import (
    AUTH_SENTENCE,
    GUIDE_SENTENCE,
    LANG_SENTENCE,
    LEN_SENTENCE,
    SPEC_URL,
    guide_fetch,
    guide_reader,
    planner_after_autorun,
    raw,
    reader_reply,
    standard_fetch,
    standard_reader,
)
from tests.factories import make_doc
from tests.fetch_fakes import SUB_URL, FakeFetchPort, make_result, redirect
from tests.test_agent_run import go, verdicts

LEAK_SENTENCE = "公開説明文にメールアドレスを記載してはならない。"
PROHIBITED_GUIDE = "テスト用アカウントの案内を載せてはならない。"
RUNTIME_SENTENCE = "提出物はCloud Run上で動作すること。"
# 否定語を含む文の直前の文は、引用検証が推測へ落とす（quotes.semantics）。否定を含む文（認証・漏洩・禁止）は、間に区切りの文を挟んで並べる
SPEC = make_doc(
    "D1",
    "\u001e".join([LANG_SENTENCE, "以上が条件です。", AUTH_SENTENCE, LEN_SENTENCE, RUNTIME_SENTENCE, GUIDE_SENTENCE, "以上が条件です。",
                   LEAK_SENTENCE, "以上が禁止事項です。", PROHIBITED_GUIDE]),
)
QC = QuoteChecker(DocIndex([SPEC]))


def requirement(rid: str, quote: str, kind: Kind, cc: CheckClass):
    out = QC.begin(raw(quote, kind, cc), rid)
    assert out.requirement is not None
    return out.requirement


R_LEN = requirement("R1", LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT)
R_AUTH = requirement("R2", AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL)
R_LEAK = requirement("R3", LEAK_SENTENCE, Kind.PROHIBITED, CheckClass.LEAK)
R_RUN = requirement("R4", RUNTIME_SENTENCE, Kind.REQUIRED, CheckClass.RUNTIME_SIGNATURE)
R_GUIDE = requirement("R5", GUIDE_SENTENCE, Kind.REQUIRED, CheckClass.GUIDANCE_PRESENT)
R_NO_GUIDE = requirement("R6", PROHIBITED_GUIDE, Kind.PROHIBITED, CheckClass.GUIDANCE_PRESENT)
R_NONE = requirement("R7", LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE)
ALL = (R_LEN, R_AUTH, R_LEAK, R_RUN, R_GUIDE, R_NO_GUIDE, R_NONE)


def plan(reqs=ALL, **kw):
    kw.setdefault("has_submission_url", True)
    kw.setdefault("has_submission_doc", True)
    return plan_autorun(reqs, **kw)


def shape(p):
    return [(s.kind.value, s.checker.value if s.checker else None, s.req_id) for s in p.steps]


# ---- 計画 ----------------------------------------------------------------------------------------
def test_the_plan_probes_once_first_and_then_runs_each_checkable_requirement_in_order():
    assert shape(plan()) == [
        ("probe", None, None),
        ("check", "text_length", "R1"),
        ("check", "auth_wall", "R2"),
        ("check", "leak_scan", "R3"),
        ("check", "cloud_run_signature", "R4"),
        ("check", "contains_terms", "R5"),
    ]  # R6（禁止の案内）と R7（検査の無い要件）は走らせない


def test_the_plan_is_a_pure_function_of_its_inputs():
    assert plan() == plan()


def test_no_probe_is_planned_when_no_check_needs_one():
    assert shape(plan([R_LEN, R_GUIDE])) == [("check", "text_length", "R1"), ("check", "contains_terms", "R5")]


def test_checks_whose_premises_are_missing_are_not_planned():
    assert shape(plan(has_submission_url=False)) == [
        ("check", "text_length", "R1"), ("check", "leak_scan", "R3"), ("check", "contains_terms", "R5"),
    ]
    assert shape(plan(has_submission_doc=False)) == [
        ("probe", None, None), ("check", "auth_wall", "R2"), ("check", "cloud_run_signature", "R4"),
    ]
    assert plan(has_submission_url=False, has_submission_doc=False).steps == ()


def test_contains_terms_waits_for_the_guidance_pages_when_there_are_unfollowed_docs_links():
    p = plan(defer_terms=True)
    assert "contains_terms" not in [s.checker.value for s in p.steps if s.checker] and p.deferred == ("R5",)
    assert len(p.steps) == 5


def test_a_prohibited_presence_check_is_never_planned():
    assert "R6" not in [s.req_id for s in plan().steps] and plan(defer_terms=True).deferred == ("R5",)


def test_max_steps_cuts_the_tail_and_reports_how_many_were_left_for_inspect():
    p = plan(max_steps=2)
    assert shape(p) == [("probe", None, None), ("check", "text_length", "R1")] and p.cut == 4
    assert plan(max_steps=0).steps == () and plan(max_steps=99).cut == 0


def test_a_step_converts_to_the_tool_call_the_governor_admits():
    s = plan().steps
    assert (s[0].kind, s[0].tool_call().name, s[0].tool_call().args.target) == (StepKind.PROBE, C.ToolName.HTTP_PROBE, "SUBMISSION_URL")
    assert (s[1].tool_call().name, s[1].tool_call().args.checker, s[1].tool_call().args.req_id) == (C.ToolName.RUN_CHECK, C.Checker.TEXT_LENGTH, "R1")


# ---- 直接実行 ------------------------------------------------------------------------------------
def sub_doc(text: str = "これは架空の作品の説明文です。" * 12):
    return make_doc("D2", text, role=DocRole.SUBMISSION)


async def test_direct_run_probes_once_and_feeds_the_probe_to_the_later_checks():
    login = make_result(redirects=(redirect(),), body='<h1>ログイン</h1><form><input type="password" name="p"></form>',
                        final_url="https://svc.example.invalid/fx/defect/login/")  # fmt: skip
    fetch = FakeFetchPort(login)
    ids = iter(f"O{i}" for i in range(1, 20))
    obs = await autorun([R_LEN, R_AUTH, R_GUIDE], CheckContext(docs={"D2": sub_doc()}), fetch, submission_url=SUB_URL, next_obs_id=lambda: next(ids))
    assert [(o.obs_id, o.tool.value, o.checker.value if o.checker else None, o.req_id, o.code.value) for o in obs] == [
        ("O1", "http_probe", None, None, "AUTH_WALL"),
        ("O2", "run_check", "text_length", "R1", "OVER_LIMIT"),
        ("O3", "run_check", "auth_wall", "R2", "AUTH_WALL"),
        ("O4", "run_check", "contains_terms", "R5", "TERMS_ABSENT"),
    ]
    assert len(fetch.calls) == 1 and fetch.calls[0].mode is C.FetchMode.PROBE  # 提出URLへの取得は probe の1回だけ


async def test_an_executor_takes_over_every_step_and_a_none_means_not_admitted():
    seen = []

    async def execute(step):
        seen.append(step.req_id)
        return None if step.req_id == "R1" else make_obs(step)

    def make_obs(step):
        return C.Observation(obs_id="O1", tool=C.ToolName.HTTP_PROBE, code=C.ObsCode.OK, outcome=C.ObsOutcome.PASS)

    fetch = FakeFetchPort(make_result())
    out = await autorun([R_LEN, R_AUTH], CheckContext(docs={"D2": sub_doc()}), fetch, submission_url=SUB_URL, next_obs_id=lambda: "O9", execute=execute)
    assert seen == [None, "R1", "R2"] and len(out) == 2
    assert fetch.calls == []  # 実行を任せた時は、AUTORUN 自身は取得しない


# ---- Reader の提案の裏取り -----------------------------------------------------------------------
@pytest.mark.parametrize("proposed", list(PageClass))
def test_the_page_class_the_code_computed_always_wins_over_the_readers_proposal(proposed):
    for code in PageClass:
        doc = make_doc("D2", "x" * 50, role=DocRole.SUBMISSION, page_class=code)
        adopted, matched = confirm_page_class(proposed, doc)
        assert adopted is code and matched is (proposed is code)


async def test_a_reader_that_calls_a_content_page_a_login_wall_changes_nothing_and_is_recorded_as_not_adopted():
    reader = standard_reader()
    reader._steps[0] = reader_reply(*(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT), raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL)),
                                    page_class=PageClass.LOGIN_WALL)  # fmt: skip
    res = await go(reader=reader)
    v = verdicts(res)
    assert v["R1"].label is C.VerdictLabel.FAIL and v["R2"].label is C.VerdictLabel.FAIL  # 検査は減らない
    ev = [e for e in res.events if e.type is TraceType.AUTORUN and e.name == "reader_proposal"]
    assert len(ev) == 1 and ev[0].attrs == {"field": "page_class", "proposed": "login_wall", "code": "content", "adopted": False}
    assert ev[0].actor is C.Actor.VERIFIER


async def test_a_reader_cannot_turn_an_ordinary_link_into_a_login_link_nor_hide_a_real_login_link():
    reader = standard_reader()
    reader._steps[0] = reader_reply(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),
                                    link_roles=[{"link_id": "L1", "role": "login"}, {"link_id": "L2", "role": "other"}])  # fmt: skip
    fetch = standard_fetch()
    html = '<html><body><p>応募要項。{}</p><a href="/event/rules">規約</a><a href="/login">ログイン</a></body></html>'.format(LEN_SENTENCE)
    fetch.routes[(SPEC_URL, C.FetchMode.PAGE)] = make_result(SPEC_URL, body=html)
    res = await go(reader=reader, fetch=fetch)
    roles = {k: r.entry.role for k, r in res.state.links.items()}
    assert roles["L1"] is C.LinkRole.OTHER and roles["L2"] is C.LinkRole.LOGIN


# ---- Governor・トレース・予算を通る --------------------------------------------------------------
async def test_autorun_calls_go_through_the_governor_and_leave_request_and_result_events():
    res = await go()
    ev = [e for e in res.events if e.phase is C.Phase.AUTORUN]
    assert [e.type.value for e in ev if e.type in (TraceType.TOOL_REQUEST, TraceType.TOOL_RESULT)] == ["tool_request", "tool_result"] * 3
    assert [(e.name, e.req_id) for e in ev if e.type is TraceType.TOOL_REQUEST] == [("http_probe", None), ("run_check", "R1"), ("run_check", "R2")]
    assert {e.actor for e in ev if e.type is TraceType.TOOL_REQUEST} == {C.Actor.GOVERNOR}  # 計画を決めたのはコード（Planner ではない）
    plan_ev = next(e for e in ev if e.type is TraceType.AUTORUN and e.name == "plan")
    assert plan_ev.attrs == {"steps": 3, "deferred": 0, "cut": 0, "probe": True}
    b = res.record.budget
    assert RUN_CAPS.tool_calls - b.tool_calls_left == 4 and RUN_CAPS.fetches_total - b.fetches_left == 3  # probe+2検査+finish／取得は 要項・提出物・probe
    assert [o.req_id for o in res.record.observations] == [None, "R1", "R2"]


async def test_the_same_checks_are_not_asked_twice_and_nothing_is_denied():
    for mode in (InspectMode.ROUTER, InspectMode.PLANNER):
        res = await go(mode)
        assert res.record.summary.denied == 0 and res.record.status is C.RunStatus.DONE
        assert len([o for o in res.record.observations if o.tool is C.ToolName.HTTP_PROBE]) == 1


async def test_autorun_leaves_calls_for_the_planner():
    caps = RUN_CAPS.model_copy(update={"tool_calls": AUTORUN_RESERVE_CALLS + 2})
    res = await go(InspectMode.PLANNER, caps=caps)
    plan_ev = next(e for e in res.events if e.type is TraceType.AUTORUN and e.name == "plan")
    assert plan_ev.attrs["steps"] == 2 and plan_ev.attrs["cut"] == 1  # probe+R1 までで止め、残り（R2）は INSPECT へ


async def test_a_denied_probe_does_not_pile_up_denials_for_the_checks_that_need_it():
    caps = RUN_CAPS.model_copy(update={"fetches_probe": 0})
    res = await go(caps=caps)
    denials = [e.reason_code for e in res.events if e.phase is C.Phase.AUTORUN and e.decision is C.Decision.DENY]
    assert denials == ["TOOL_NOT_ALLOWED"]  # probe の拒否1件だけ。依存する auth_wall は走らせず、PROBE_FIRST の拒否を重ねない
    assert [o.req_id for o in res.record.observations] == ["R1"]


# ---- router と Planner の結論は同じ（AUTORUN を共用しているので）----------------------------------
@pytest.mark.parametrize("variant", gen.VARIANTS, ids=lambda v: v.name)
async def test_router_and_planner_reach_the_same_conclusions_on_every_fixture_variant(variant):
    (a, _), (b, _) = await run_variant(variant), await run_variant(variant, inspect_mode=InspectMode.PLANNER, planner_model=planner_after_autorun())
    key = lambda r: [(v.req_id, v.label, v.reason_code, v.reason, [e.label for e in v.evidence]) for v in r.verdicts]  # noqa: E731
    assert key(a) == key(b) and a.contradictions == b.contradictions and a.status is b.status is C.RunStatus.DONE


async def test_the_sample_defect_keeps_its_known_result_three_failures_and_one_contradiction():
    """②は案内ページ付き。案内ページを辿る Planner なら、D1〜D4（不適合3＋矛盾1）だけが出て、案内の要件は推定適合になる。"""
    record, row = await run_variant(gen.BASE_DEFECT, inspect_mode=InspectMode.PLANNER, planner_model=RulePlanner())
    labels = [v.label for v in record.verdicts]
    assert labels.count(C.VerdictLabel.FAIL) == 3 and len(record.contradictions) == 1 and row["false_positives"] == 0
    assert row["false_absent"] == 0 and row["missed"] == []
    assert labels.count(C.VerdictLabel.UNVERIFIABLE) == 4 and labels.count(C.VerdictLabel.REFERENCE) == 0
    assert labels.count(C.VerdictLabel.PRESUMED_PASS) == 1
    assert sum(1 for e in record.events if e.type is TraceType.REPLAN) == 1


async def test_the_sample_defect_read_by_the_router_alone_misses_the_guide_page_as_a_false_absent():
    """対照: router は案内ページを辿らない＝説明ページだけを見て「無い」と言う（誤った absent）。②が方針変更を見せる理由。"""
    _, row = await run_variant(gen.BASE_DEFECT)
    assert row["false_absent"] == 1 and row["missed"] == ["G1"]


async def test_the_router_runs_what_autorun_left_but_does_not_follow_links_so_it_misses_a_guide_on_another_page():
    """対照: router は案内ページを辿らない。説明ページに案内が無いので contains_terms は「無い」を返し、判定表は不適合にする
    （案内ページには在る＝誤った absent。Planner が辿れば推定適合になる: tests/test_agent_replan.py）。"""
    res = await go(InspectMode.ROUTER, fetch=guide_fetch(), reader=guide_reader())
    v = verdicts(res)
    assert v["R3"].label is C.VerdictLabel.FAIL and v["R3"].evidence[0].label == "求められた語が本文に無い"
    plan_ev = next(e for e in res.events if e.type is TraceType.AUTORUN and e.name == "plan")
    assert plan_ev.attrs["deferred"] == 1  # AUTORUN は前提が揃わないので走らせず、router が残りとして走らせた
    assert [o.checker.value for o in res.record.observations if o.req_id == "R3"] == ["contains_terms"]
