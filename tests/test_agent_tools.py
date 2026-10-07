"""tools.py: 実行・観測の整形・予算の計上・想定内の失敗の扱い。"""
import pytest

from app.agent.tools import TOOL_DESCRIPTIONS, ToolRegistry
from app.config import RUN_CAPS
from app.contracts import (
    CheckClass,
    ContentKind,
    DocRole,
    FetchKind,
    FetchLimit,
    FetchMode,
    FetchOutcome,
    FunctionCall,
    Kind,
    LinkEntry,
    LinkRole,
    ObsCode,
    ObsOutcome,
    PolicyId,
    ToolName,
    TraceType,
    UnverifiableReason,
)
from app.errors import AppError, ErrorCode
from tests.agent_support import (
    AUTH_SENTENCE,
    LEN_SENTENCE,
    LOGIN_HTML,
    LOGIN_URL,
    SVC_HOST,
    RoutedFetch,
    make_world,
    raw,
)
from tests.factories import make_doc
from tests.fetch_fakes import SUB_URL, SleepRecorder, make_result, redirect, timeout_result

REQS = (
    raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),
    raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
)
LONG = "あ" * 120
LINK_URL = f"https://{SVC_HOST}/fx/defect/extra/"


def setup(fetch=None, *, submission_text=LONG, caps=RUN_CAPS):
    state, gov = make_world(reqs=REQS, submission_text=submission_text, caps=caps)
    reg = ToolRegistry(state=state, governor=gov, fetch=fetch or RoutedFetch({}), sleep=SleepRecorder())
    gov.begin_turn(1, 8, gov.allowed_tools())
    return state, gov, reg


def call(gov, name, **args):
    adm = gov.admit(FunctionCall(name=name, args=args))
    assert adm.allowed, (adm.policy, adm.reason)
    return adm


def add_link(state, href=LINK_URL, role=LinkRole.OTHER, parent_role=DocRole.SUBMISSION):
    state.add_doc(make_doc("D3", "リンクのある文書", role=parent_role,
                           links=(LinkEntry(link_id="L1", href=href, anchor_text="追加ページ", role=role, in_scope=True),)))


def test_every_tool_has_a_description_and_a_declaration_only_when_allowed():
    assert set(TOOL_DESCRIPTIONS) == set(ToolName)
    decls = ToolRegistry.declarations((ToolName.FINISH, ToolName.RUN_CHECK))
    assert [d.name for d in decls] == [ToolName.FINISH, ToolName.RUN_CHECK]
    assert all(len(d.description) <= 500 for d in decls)
    assert "properties" in decls[1].parameters and "req_id" in decls[1].parameters["properties"]


async def test_run_check_text_length_returns_a_code_observation_and_updates_state():
    state, gov, reg = setup()
    res = await reg.execute(call(gov, "run_check", checker="text_length", req_id="R1"))
    assert res.code is ObsCode.OVER_LIMIT and res.observation.outcome is ObsOutcome.FAIL
    assert state.observations == [res.observation] and state.last_observation is ObsCode.OVER_LIMIT
    ev = [e for e in gov.trace.events if e.type is TraceType.TOOL_RESULT]
    assert len(ev) == 1 and res.observation.event_seq == ev[0].seq and ev[0].obs_id == res.observation.obs_id
    assert ev[0].result_digest and ev[0].req_id == "R1"


async def test_requirement_with_a_conclusive_observation_becomes_done():
    from app.contracts import ReqState

    state, gov, reg = setup()
    await reg.execute(call(gov, "run_check", checker="text_length", req_id="R1"))
    assert state.req_state(state.req("R1")) is ReqState.DONE
    assert state.req_state(state.req("R2")) is ReqState.OPEN


async def test_unimplemented_checker_becomes_an_inconclusive_observation_not_an_exception():
    # 案内の話題の引用を持つ要件（G3 の差し込み口 contains_terms を呼ぶ。leak_scan は第3弾で実装済み）
    state2, gov2 = make_world(reqs=(raw("提出物には審査員向けの使い方の案内を記載すること。", Kind.REQUIRED, CheckClass.GUIDANCE_PRESENT),),
                              spec_text="応募要項\u001e提出物には審査員向けの使い方の案内を記載すること。")
    reg2 = ToolRegistry(state=state2, governor=gov2, fetch=RoutedFetch({}))
    gov2.begin_turn(1, 8, gov2.allowed_tools())
    res = await reg2.execute(call(gov2, "run_check", checker="contains_terms", req_id="R1"))
    assert res.code is ObsCode.ERROR and res.observation.outcome is ObsOutcome.INCONCLUSIVE
    assert res.observation.facts == {"why": "not_implemented"}


async def test_a_crashing_checker_does_not_crash_the_run_and_leaks_no_message(monkeypatch):
    import app.agent.tools as tools

    def boom(*a, **k):
        raise RuntimeError("secret-internal-detail https://leak.invalid/")

    state, gov, reg = setup()
    monkeypatch.setattr(tools, "run_checker", boom)
    res = await reg.execute(call(gov, "run_check", checker="text_length", req_id="R1"))
    assert res.observation.facts == {"why": "checker_error"}
    assert "secret" not in "".join(e.model_dump_json() for e in gov.trace.events) + res.observation.model_dump_json()


async def test_run_check_without_a_submission_document_is_inconclusive():
    state, gov, reg = setup()
    del state.docs["D2"]
    state.submission_doc_id = None
    res = await reg.execute(call(gov, "run_check", checker="text_length", req_id="R1"))
    assert res.code is ObsCode.ERROR and res.observation.outcome is ObsOutcome.INCONCLUSIVE


async def test_probe_records_an_observation_charges_the_probe_budget_and_marks_the_target():
    fetch = RoutedFetch({(SUB_URL, FetchMode.PROBE): make_result(SUB_URL, redirects=(redirect(),), final_url=LOGIN_URL, body=LOGIN_HTML)})
    state, gov, reg = setup(fetch)
    res = await reg.execute(call(gov, "http_probe", target="SUBMISSION_URL", reason="確認"))
    assert res.code is ObsCode.AUTH_WALL and res.observation.facts["target"] == "SUBMISSION_URL"
    assert [c.mode for c in fetch.calls] == [FetchMode.PROBE] and [c.url for c in fetch.calls] == [SUB_URL]
    b = gov.meter.budget
    assert b.fetches_by_kind == {FetchKind.HTTP_PROBE: 1} and b.fetches == 1
    assert "SUBMISSION_URL" in state.probed_targets and state.probes() == (state.observations[0],)


async def test_probe_retries_are_charged_per_attempt():
    fetch = RoutedFetch({(SUB_URL, FetchMode.PROBE): timeout_result(SUB_URL)})
    state, gov, reg = setup(fetch)
    res = await reg.execute(call(gov, "http_probe", target="SUBMISSION_URL", reason="確認"))
    assert res.code is ObsCode.TRANSIENT and len(fetch.calls) == 2  # 一時的な失敗は1回だけ再試行（S-04）
    assert gov.meter.budget.fetches == 2  # 取得した回数ぶん、予算に数える


async def test_fetch_layer_exception_becomes_an_inconclusive_observation_with_only_the_error_code():
    fetch = RoutedFetch({(SUB_URL, FetchMode.PROBE): AppError(ErrorCode.INTERNAL, "token=abc https://x.invalid/")})
    state, gov, reg = setup(fetch)
    res = await reg.execute(call(gov, "http_probe", target="SUBMISSION_URL", reason="確認"))
    assert res.code is ObsCode.ERROR and res.observation.facts["error"] == "internal"
    assert "abc" not in res.observation.model_dump_json()
    assert gov.meter.budget.fetches == 1  # 失敗でも1回は数える


async def test_blocked_probe_is_a_blocked_observation():
    fetch = RoutedFetch({(SUB_URL, FetchMode.PROBE): make_result(
        SUB_URL, outcome=FetchOutcome.BLOCKED, blocked_policy=PolicyId.SCOPE, content_kind=None, headers={})})
    state, gov, reg = setup(fetch)
    res = await reg.execute(call(gov, "http_probe", target="SUBMISSION_URL", reason="確認"))
    assert res.code is ObsCode.BLOCKED and res.observation.outcome is ObsOutcome.INCONCLUSIVE


async def test_probe_of_a_link_uses_the_link_table_href_not_a_model_supplied_url():
    fetch = RoutedFetch({(LINK_URL, FetchMode.PROBE): make_result(LINK_URL, body="<p>" + "あ" * 600 + "</p>")})
    state, gov, reg = setup(fetch)
    add_link(state)
    gov.begin_turn(2, 8, gov.allowed_tools())
    res = await reg.execute(call(gov, "http_probe", target="L1", reason="確認"))
    assert res.observation.facts["target"] == "L1" and [c.url for c in fetch.calls] == [LINK_URL]


async def test_fetch_link_adds_a_sanitized_document_with_the_parent_role_and_marks_the_link_fetched():
    page = "<html><body><h1>追加</h1><p>追加ページの本文です。</p></body></html>"
    fetch = RoutedFetch({(LINK_URL, FetchMode.PAGE): make_result(LINK_URL, body=page)})
    state, gov, reg = setup(fetch)
    add_link(state)
    gov.begin_turn(2, 8, gov.allowed_tools())
    res = await reg.execute(call(gov, "fetch_link", link_id="L1", reason="追加ページを読む"))
    assert res.code is ObsCode.OK and res.observation.facts["doc"] == "D4"
    doc = state.docs["D4"]
    assert doc.role is DocRole.SUBMISSION and "追加ページの本文です" in doc.visible_text
    assert "L1" in state.fetched_links and state.submission_doc_id == "D2"  # 検査対象の提出物は最初の1つのまま
    assert gov.meter.budget.fetches == 1
    assert ToolName.FETCH_LINK not in gov.allowed_tools()  # 取得済みのリンクはもう出ない


async def test_fetch_link_from_a_spec_document_is_registered_as_spec():
    page = "<html><body><p>別の要項ページ。</p></body></html>"
    fetch = RoutedFetch({(LINK_URL, FetchMode.PAGE): make_result(LINK_URL, body=page)})
    state, gov, reg = setup(fetch)
    add_link(state, parent_role=DocRole.SPEC)
    gov.begin_turn(2, 8, gov.allowed_tools())
    await reg.execute(call(gov, "fetch_link", link_id="L1", reason="r"))
    assert state.docs["D4"].role is DocRole.SPEC


@pytest.mark.parametrize(
    "result,code",
    [
        (make_result(LINK_URL, outcome=FetchOutcome.BLOCKED, blocked_policy=PolicyId.SSRF_IP, content_kind=None, headers={}), ObsCode.BLOCKED),
        (make_result(LINK_URL, outcome=FetchOutcome.TIMEOUT, limit_hit=FetchLimit.TOTAL_TIMEOUT, content_kind=None, headers={}), ObsCode.TRANSIENT),
        (make_result(LINK_URL, outcome=FetchOutcome.UNSUPPORTED_TYPE, content_kind=ContentKind.UNSUPPORTED, headers={}), ObsCode.UNSUPPORTED_TYPE),
        (make_result(LINK_URL, outcome=FetchOutcome.TOO_LARGE, limit_hit=FetchLimit.CONTENT_LENGTH, content_kind=None, headers={}), ObsCode.ERROR),
    ],
)
async def test_fetch_link_failures_are_inconclusive_observations_and_add_no_document(result, code):
    state, gov, reg = setup(RoutedFetch({(LINK_URL, FetchMode.PAGE): result}))
    add_link(state)
    gov.begin_turn(2, 8, gov.allowed_tools())
    res = await reg.execute(call(gov, "fetch_link", link_id="L1", reason="r"))
    assert res.code is code and res.observation.outcome is ObsOutcome.INCONCLUSIVE
    assert set(state.docs) == {"D1", "D2", "D3"}


async def test_fetch_link_exceptions_are_contained():
    state, gov, reg = setup(RoutedFetch({(LINK_URL, FetchMode.PAGE): AppError(ErrorCode.FETCH_BLOCKED, "x")}))
    add_link(state)
    gov.begin_turn(2, 8, gov.allowed_tools())
    res = await reg.execute(call(gov, "fetch_link", link_id="L1", reason="r"))
    assert res.code is ObsCode.BLOCKED and gov.meter.budget.fetches == 1


async def test_mark_unverifiable_records_a_planner_mark_with_the_premise():
    from app.contracts import Observation

    state, gov, reg = setup()
    state.observations.append(Observation(obs_id="O1", tool=ToolName.HTTP_PROBE, code=ObsCode.AUTH_WALL, outcome=ObsOutcome.FAIL, strong=True,
                                          facts={"target": "SUBMISSION_URL", "access": "login_redirect"}))
    state.requirements.append(state.requirements[0].model_copy(update={"req_id": "R3", "check_class": CheckClass.NONE}))
    gov.begin_turn(2, 8, gov.allowed_tools())
    res = await reg.execute(call(gov, "mark_unverifiable", req_id="R3", reason_code="NEEDS_AUTH"))
    m = state.marks["R3"]
    assert res.mark == m and m.by_planner and m.reason_code is UnverifiableReason.NEEDS_AUTH and m.premise_obs_id == "O1"
    assert res.code is None  # Planner へ返る観測コードは付かない（last_observation も動かない）


async def test_finish_returns_finished_and_the_unadmitted_cannot_be_executed():
    state, gov, reg = setup()
    for rid, chk in (("R1", "text_length"), ("R2", "auth_wall")):
        await reg.execute(call(gov, "run_check", checker=chk, req_id=rid))
    res = await reg.execute(call(gov, "finish"))
    assert res.finished
    denied = gov.admit(FunctionCall(name="nope", args={}))
    with pytest.raises(ValueError):
        await reg.execute(denied)


async def test_nothing_returned_to_the_planner_contains_page_text():
    """Planner へ戻るのは ObsCode（1語）だけ。観測の facts にも本文・URL・アンカー文言が載らない。"""
    fetch = RoutedFetch({(SUB_URL, FetchMode.PROBE): make_result(SUB_URL, redirects=(redirect(),), final_url=LOGIN_URL, body=LOGIN_HTML)})
    state, gov, reg = setup(fetch)
    res = await reg.execute(call(gov, "http_probe", target="SUBMISSION_URL", reason="確認"))
    dumped = res.observation.model_dump_json()
    assert "ログイン" not in dumped and "https://" not in dumped and SVC_HOST not in dumped
    assert isinstance(res.code, ObsCode)
