"""run.py: オフラインで縦に1本通る（Reader → 引用検証 → router/Planner → 検査 → adjudicate → JSON/HTML）。
停止条件（DEGRADED・ABORTED）・攻撃（モデルが判定に影響しようとする）・構造（判定を書けるのは adjudicate.py だけ）。"""
import ast
import json
from pathlib import Path

import pytest

from app.agent.planner import InspectMode
from app.agent.report import report_html, report_json
from app.agent.run import run_audit
from app.agent.trace import to_jsonl
from app.config import RUN_CAPS, Settings
from app.contracts import (
    AbortReason,
    CheckClass,
    DegradedReason,
    Kind,
    Phase,
    RunRecord,
    RunStatus,
    TraceType,
    UnverifiableReason,
    VerdictLabel,
)
from app.errors import AppError, ErrorCode
from app.model.scripted import ScriptedPort, reply_calls
from tests.agent_support import (
    AUTH_SENTENCE,
    INJECTION,
    LANG_SENTENCE,
    LEN_SENTENCE,
    PRESET,
    SPEC_URL,
    FakeClock,
    guide_fetch,
    guide_reader,
    RoutedFetch,
    raw,
    reader_reply,
    standard_fetch,
    planner_after_autorun,
    standard_reader,
)
from tests.factories import seal
from tests.fetch_fakes import SUB_URL, make_result

L, P, F = VerdictLabel, Phase, TraceType


def verdicts(res):
    return {v.req_id: v for v in res.record.verdicts}


async def go(mode=InspectMode.ROUTER, *, fetch=None, reader=None, planner=None, **kw):
    return await run_audit(
        PRESET,
        fetch=fetch or standard_fetch(),
        reader_model=reader or standard_reader(),
        planner_model=planner if planner is not None else (planner_after_autorun() if mode is InspectMode.PLANNER else None),
        inspect_mode=mode,
        **kw,
    )


# ---- 完了条件: オフラインで1本通る -----------------------------------------------------------------------
@pytest.mark.parametrize("mode", [InspectMode.ROUTER, InspectMode.PLANNER])
async def test_full_offline_run_from_reader_to_json_and_html(mode):
    res = await go(mode)
    rec = res.record
    assert (rec.status, rec.degraded_reason, rec.aborted_reason) == (RunStatus.DONE, None, None)
    v = verdicts(res)
    assert v["R1"].label is L.FAIL and "186字" in v["R1"].evidence[0].label  # 説明文が上限100字を超える（観測 text_length）
    assert v["R2"].label is L.FAIL and "302→/fx/defect/login/" in v["R2"].evidence[0].label  # 提出URLがログインへ転送される
    assert all(r.reverified for r in rec.requirements) and [r.span.original_span for r in rec.requirements] == [LEN_SENTENCE, AUTH_SENTENCE]
    assert {e.obs_id for x in v.values() for e in x.evidence} <= {o.obs_id for o in rec.observations}
    assert rec.summary.quotes_verbatim == 2 and rec.summary.injection_visible == 1 and rec.summary.denied == 0
    # JSON は契約の唯一の入口を通り、往復できる
    text = report_json(rec)
    back = RunRecord.restore_json(text, seal=seal())
    assert back.verdicts == rec.verdicts and back.status is RunStatus.DONE
    # HTML は素の表（スクリプト無し）
    html = report_html(rec)
    assert "<table" in html and "<script" not in html and "不適合" in html and LEN_SENTENCE in html
    assert "186字" in html and "要件 2 件" in html


async def test_phases_are_entered_in_order_and_every_event_belongs_to_the_run():
    res = await go()
    phases = [e.name for e in res.events if e.type is F.PHASE_ENTER]
    assert phases == ["ACQUIRE", "READ", "AUTORUN", "INSPECT", "ADJUDICATE", "REPORT", "DONE"]
    assert [e.seq for e in res.events] == sorted(e.seq for e in res.events)
    assert {e.run_id for e in res.events} == {res.record.run_id}
    assert [e.req_id for e in res.events if e.type is F.VERDICT] == ["R1", "R2"]
    assert all(e.verdict is not None for e in res.events if e.type is F.VERDICT)
    assert to_jsonl(res.events).count("\n") == len(res.events)


async def test_router_and_planner_agree_on_verdicts():
    a, b = await go(InspectMode.ROUTER), await go(InspectMode.PLANNER)
    assert [(v.req_id, v.label, v.reason_code, v.reason) for v in a.record.verdicts] == [
        (v.req_id, v.label, v.reason_code, v.reason) for v in b.record.verdicts]
    assert a.record.planner_model == "router" and b.record.planner_model == "scripted-planner"


async def test_only_the_preset_urls_are_fetched_and_only_in_the_expected_modes():
    fetch = standard_fetch()
    await go(fetch=fetch)
    assert [(c.url, c.mode.value) for c in fetch.calls] == [(SPEC_URL, "page"), (SUB_URL, "page"), (SUB_URL, "probe")]


async def test_a_run_with_the_real_safefetch_over_the_fake_network():
    """FetchPort の実装を SafeFetch（偽のネットワーク層）に替えても同じ結果になる。"""
    from app.net.vectors import LP_HOST, SVC_HOST, Reply
    from tests.net_support import make_rig
    from tests.agent_support import PREFIXES, SPEC_HTML, SUBMISSION_HTML

    html = (("Content-Type", "text/html; charset=utf-8"),)
    rig = make_rig(
        {
            f"{LP_HOST}/event": Reply(headers=html, body=SPEC_HTML.encode()),
            f"{SVC_HOST}/fx/defect/submission/": Reply(headers=html, body=SUBMISSION_HTML.encode()),
        },
        prefixes=PREFIXES,
    )
    res = await run_audit(PRESET, fetch=rig.fetch, reader_model=standard_reader(), inspect_mode=InspectMode.ROUTER)
    v = verdicts(res)
    assert v["R1"].label is L.FAIL  # 字数超過（提出物を実際に取得して数えた）
    assert v["R2"].label is L.PASS  # この偽ネットワークでは提出URLが開ける
    assert res.record.status is RunStatus.DONE


async def test_more_seeds_than_the_acquire_cap_keep_the_submission_and_do_not_degrade():
    from app.contracts import FetchMode, Preset, UrlPrefix
    from tests.agent_support import LP_HOST, SPEC_HTML, SVC_HOST, SUBMISSION_HTML

    seeds = tuple(f"https://{LP_HOST}/s{i}" for i in range(1, 4))
    preset = Preset(preset_id="sample_defect", label_ja="x", kind="fixture_defect", spec_seed_urls=seeds, submission_url=SUB_URL,  # type: ignore[arg-type]
                    allowed_prefixes=(*(UrlPrefix(host=LP_HOST, path_prefix=f"/s{i}", exact=True) for i in range(1, 4)), UrlPrefix(host=SVC_HOST, path_prefix="/fx/")))
    fetch = RoutedFetch({**{(u, FetchMode.PAGE): make_result(u, body=SPEC_HTML) for u in seeds}, (SUB_URL, FetchMode.PAGE): make_result(SUB_URL, body=SUBMISSION_HTML)})
    reader = standard_reader(reader_reply())  # 読める要項は2文書＝Reader の呼び出しは2回
    res = await run_audit(preset, fetch=fetch, reader_model=reader, inspect_mode=InspectMode.ROUTER)
    assert res.record.status is RunStatus.DONE
    assert [(c.url, c.mode.value) for c in fetch.calls[:3]] == [(seeds[0], "page"), (seeds[1], "page"), (SUB_URL, "page")]  # 末尾のシードを落とし、提出物を残す
    assert seeds[2] not in [c.url for c in fetch.calls]
    assert {v.req_id: v.label for v in res.record.verdicts}["R1"] is L.FAIL


# ---- 停止条件 ---------------------------------------------------------------------------------------
async def test_budget_exhaustion_is_degraded_not_an_exception_and_unchecked_requirements_say_why():
    caps = RUN_CAPS.model_copy(update={"tool_calls": 1})
    res = await go(caps=caps)
    rec = res.record
    assert (rec.status, rec.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.BUDGET)
    for v in rec.verdicts:
        assert v.label is L.UNVERIFIABLE and v.reason_code is UnverifiableReason.BUDGET
    assert len(rec.verdicts) == len(rec.requirements) == 2  # 未検査の要件も、理由コードつきで必ず出す
    assert "部分結果" in report_html(rec)


async def test_degraded_run_keeps_evidence_for_what_was_already_checked():
    """ツール3回の上限（probe → R1 → R2 の途中で尽きる）。検査済みの R1 は不適合のまま、未検査の R2 だけ確認不能。"""
    caps = RUN_CAPS.model_copy(update={"tool_calls": 2})
    res = await go(caps=caps)
    v = verdicts(res)
    assert v["R1"].label is L.FAIL and v["R2"].label is L.UNVERIFIABLE and v["R2"].reason_code is UnverifiableReason.BUDGET
    assert res.record.degraded_reason is DegradedReason.BUDGET


async def test_reader_failure_is_a_degraded_result_with_no_requirements():
    res = await go(reader=ScriptedPort([AppError(ErrorCode.RETRYABLE, "x")]))
    rec = res.record
    assert (rec.status, rec.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.MODEL_FAILURE)
    assert rec.requirements == () and rec.verdicts == () and report_json(rec)
    assert rec.summary.requirements_total == 0


async def test_planner_failure_keeps_what_autorun_decided_and_marks_the_rest_as_transient():
    """Planner が落ちても、AUTORUN が決めた要件（字数・認証壁）の判定は証拠のまま残る。AUTORUN で決まらなかった要件（案内ページを
    辿る前の contains_terms）だけが、理由コード TRANSIENT の確認不能になる。"""
    res = await go(InspectMode.PLANNER, planner=ScriptedPort([AppError(ErrorCode.RETRYABLE, "x")]), fetch=guide_fetch(), reader=guide_reader())
    rec = res.record
    assert rec.degraded_reason is DegradedReason.MODEL_FAILURE
    v = verdicts(res)
    assert v["R1"].label is L.FAIL and v["R2"].label is L.FAIL  # AUTORUN の検査結果は、Planner の失敗で消えない
    assert v["R3"].label is L.UNVERIFIABLE and v["R3"].reason_code is UnverifiableReason.TRANSIENT


async def test_fatal_config_error_propagates_instead_of_a_misleading_report():
    with pytest.raises(AppError) as e:
        await go(reader=ScriptedPort([AppError(ErrorCode.FATAL_CONFIG, "401")]))
    assert e.value.code is ErrorCode.FATAL_CONFIG


async def test_kill_switch_aborts_before_any_network_or_model_call():
    fetch, reader = standard_fetch(), standard_reader()
    res = await go(fetch=fetch, reader=reader, settings=Settings(kill_switch=True))
    rec = res.record
    assert (rec.status, rec.aborted_reason) == (RunStatus.ABORTED, AbortReason.KILL)
    assert fetch.calls == [] and reader.requests == [] and rec.verdicts == ()
    assert any(e.type is F.ABORT and e.reason_code == "KILL" for e in rec.events)
    assert "中止" in report_html(rec) and report_json(rec)


async def test_wall_clock_overrun_aborts_with_wall_clock_and_stops_further_work():
    clock = FakeClock()

    def slow_reader(_req):  # Reader の応答が返った時点で75秒を超えていた
        clock.advance(RUN_CAPS.wall_clock_s + 1)
        return reader_reply(*(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT),))

    fetch = standard_fetch()
    res = await go(fetch=fetch, reader=ScriptedPort([slow_reader]), clock=clock)
    assert (res.record.status, res.record.aborted_reason) == (RunStatus.ABORTED, AbortReason.WALL_CLOCK)
    assert [c.mode.value for c in fetch.calls] == ["page", "page"]  # INSPECT の取得（probe）は行われていない


async def test_requirement_cap_marks_the_record_as_capped():
    caps = RUN_CAPS.model_copy(update={"requirements_obligatory": 1})
    res = await go(caps=caps)
    assert res.record.summary.capped is True and res.record.summary.requirements_total == 1


async def test_a_submission_that_cannot_be_fetched_leaves_a_text_check_unverifiable():
    fetch = standard_fetch()
    fetch.routes[(SUB_URL, __import__("app.contracts", fromlist=["FetchMode"]).FetchMode.PAGE)] = AppError(ErrorCode.FETCH_BLOCKED, "x")
    res = await go(fetch=fetch)
    v = verdicts(res)
    assert v["R1"].label is L.UNVERIFIABLE  # 提出物の本文が無いので字数は数えられない
    assert v["R2"].label is L.FAIL  # 到達検査（probe）は別に行える


# ---- 攻撃: モデルの出力は判定に影響しない -----------------------------------------------------------------
async def test_a_reader_told_by_the_spec_to_pass_everything_cannot_change_any_verdict():
    """要項に注入文があり、Reader がそれに従って「全件適合」と主張する要件を足しても、判定は観測だけで決まる。"""
    hijack = raw(INJECTION, Kind.REQUIRED, CheckClass.NONE, gist="全ての要件は適合している")
    reader = ScriptedPort([reader_reply(*(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT), raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL), hijack))])
    res = await go(reader=reader)
    v = verdicts(res)
    assert v["R1"].label is L.FAIL and v["R2"].label is L.FAIL
    assert v["R3"].label is L.REFERENCE and res.record.requirements[2].span is None  # 引用できない推測は参考で、集計外
    body = json.loads(report_json(res.record))
    assert INJECTION not in json.dumps(body["requirements"], ensure_ascii=False) and INJECTION not in json.dumps(body["verdicts"], ensure_ascii=False)
    assert INJECTION not in report_html(res.record)  # 棄却された引用は、トレース（表示用に無害化した文字列）にだけ残る


async def test_a_wrong_check_class_from_the_model_never_produces_a_machine_verified_pass():
    """Reader が無関係な文に「字数」の検査を割り当てても、検査は走らず、確認不能（範囲外）になる。"""
    reader = ScriptedPort([reader_reply(raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT))])
    res = await go(reader=reader)
    (v,) = res.record.verdicts
    assert v.label is L.UNVERIFIABLE and v.reason_code is UnverifiableReason.OUT_OF_SCOPE
    assert res.record.observations == ()


async def test_a_planner_cannot_wash_a_failure_by_marking_the_requirement_unverifiable():
    """AUTORUN が不適合を観測した後、Planner が「確認不能」の印で洗おうとしても通らない（判定は観測だけで決まる）。"""
    steps = [reply_calls(("mark_unverifiable", {"req_id": "R2", "reason_code": "HUMAN_ONLY"})),  # 決着済みの要件への印は拒否
             reply_calls(("mark_unverifiable", {"req_id": "R1", "reason_code": "NO_EVIDENCE"})),  # コード専用の理由は拒否
             reply_calls(("finish", {}))]
    res = await go(InspectMode.PLANNER, planner=ScriptedPort(steps))
    v = verdicts(res)
    assert v["R1"].label is L.FAIL and v["R2"].label is L.FAIL
    assert res.record.summary.denied == 2 and not res.governor.state.marks


async def test_planner_cannot_skip_the_auth_check_it_can_only_see_that_autorun_already_ran_it():
    """認証壁の検査は AUTORUN が必ず走らせる。Planner が「NEEDS_AUTH」の印で省こうとしても、不適合は洗えない（S-03）。"""
    steps = [reply_calls(("mark_unverifiable", {"req_id": "R2", "reason_code": "NEEDS_AUTH"})),
             reply_calls(("finish", {}))]
    res = await go(InspectMode.PLANNER, planner=ScriptedPort(steps))
    v = verdicts(res)
    assert v["R2"].label is L.FAIL and v["R1"].label is L.FAIL
    assert [e.obs_id for e in res.events if e.type is F.TOOL_RESULT and e.name == "run_check"] == ["O2", "O3"]  # 検査は AUTORUN の中で済んでいる
    assert {e.phase for e in res.events if e.type is F.TOOL_REQUEST and e.name == "run_check"} == {P.AUTORUN}
    assert not res.governor.state.marks


async def test_a_valid_planner_mark_on_a_non_checkable_requirement_is_reported_with_its_premise():
    reader = standard_reader()
    reader._steps[0] = reader_reply(*(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT), raw(AUTH_SENTENCE, Kind.REQUIRED, CheckClass.AUTH_WALL),
                                      raw(LANG_SENTENCE, Kind.REQUIRED, CheckClass.NONE)))
    steps = [reply_calls(("mark_unverifiable", {"req_id": "R3", "reason_code": "NEEDS_AUTH"})),  # 前提の観測は AUTORUN の probe
             reply_calls(("finish", {}))]
    res = await go(InspectMode.PLANNER, planner=ScriptedPort(steps), reader=reader)
    v = verdicts(res)
    assert v["R3"].label is L.UNVERIFIABLE and v["R3"].reason_code is UnverifiableReason.NEEDS_AUTH and v["R3"].evidence  # 前提の観測が証拠に出る
    assert v["R1"].label is L.FAIL and v["R2"].label is L.FAIL


async def test_hijacked_planner_leaves_a_partial_but_truthful_report():
    steps = [reply_calls(("delete_everything", {}))] * 3 + [reply_calls(("finish", {}))]
    res = await go(InspectMode.PLANNER, planner=ScriptedPort(steps))
    rec = res.record
    assert (rec.status, rec.degraded_reason) == (RunStatus.DEGRADED, DegradedReason.DENIAL_STREAK)
    assert rec.summary.denied == 3 and len(rec.observations) == 3  # 乗っ取られても、AUTORUN の観測（probe と2つの検査）は残る
    assert {v.label for v in rec.verdicts} == {L.FAIL}  # 観測がそのまま判定になる。Planner が何を言っても適合にはならない
    assert L.PASS not in {v.label for v in rec.verdicts}


async def test_the_final_reverification_demotes_a_tampered_quote_to_a_speculative_reference():
    """REPORT 前の最終再検証（run_audit が行う）と同じ検査: 原文に当たらなくなった引用は、適合・不適合の判定を持たず推測へ落ちる。"""
    from app.contracts import DocRole
    from app.quotes import DocIndex, QuoteChecker

    res = await go()
    assert res.reverify_issues == ()  # 通常の実行では不合格は出ない
    req = res.record.requirements[0]
    forged = req.model_copy(update={"span": req.span.model_copy(update={"original_span": "あ" * len(req.span.original_span)})})
    qc = QuoteChecker(DocIndex([d for d in res.state.docs.values() if d.role is DocRole.SPEC]))
    out = qc.reverify([forged])
    assert not out.ok and out.issues[0].reason.value == "text_mismatch"
    assert out.requirements[0].kind is Kind.SPECULATIVE and out.requirements[0].span is None


# ---- 構造: 判定を書けるのは adjudicate.py だけ ---------------------------------------------------------
AGENT_FILES = sorted(list(Path("app/agent").glob("*.py")) + [Path("app/cli.py")])


def _calls(path: Path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call):
            f = node.func
            yield f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")


def test_no_module_outside_adjudicate_constructs_a_verdict():
    offenders = [p.as_posix() for p in AGENT_FILES if "Verdict" in set(_calls(p))]
    assert offenders == []
    for p in Path("app").rglob("*.py"):
        if p.as_posix() in ("app/adjudicate.py", "app/contracts.py") or p.parts[1] in ("agent",):
            continue
        assert "Verdict" not in set(_calls(p)), p


def test_adjudicate_is_called_from_exactly_one_place_in_the_agent_layer():
    users = [p.as_posix() for p in AGENT_FILES if "adjudicate" in set(_calls(p))]
    assert users == ["app/agent/run.py"]


def test_the_agent_layer_never_issues_verification_seals_nor_builds_verified_requirements():
    for p in AGENT_FILES:
        src = p.read_text(encoding="utf-8")
        assert "VerificationSeal" not in src, p
        assert "VerifiedRequirement" not in set(_calls(p)), p  # 型注釈には使う。生成はしない


def test_the_agent_layer_has_no_http_client_and_no_test_only_imports():
    banned = {"requests", "httpx", "aiohttp", "urllib3", "socket", "http", "scripted", "cassette"}
    for p in AGENT_FILES:
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else ([node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            for m in mods:
                assert m.split(".")[0] not in banned and not m.endswith((".scripted", ".cassette")), f"{p}: {m}"


def test_report_json_goes_through_the_contract_serializer_only():
    src = Path("app/agent/report.py").read_text(encoding="utf-8")
    assert "serialize_report" in src and "model_dump_json" not in src and "json.dumps" not in src


def test_no_secret_shaped_or_real_identifier_in_the_new_code():
    import re

    pat = re.compile(r"AIza[0-9A-Za-z_-]{20,}|ya29\.|BEGIN [A-Z ]*PRIVATE KEY|[a-z0-9-]+\.run\.app|@[a-z0-9-]+\.(?:ac\.jp|co\.jp|com)\b")
    for p in AGENT_FILES + sorted(Path("tests").glob("*agent*.py")) + [Path("tests/test_cli.py")]:
        if p.exists():
            assert not pat.search(p.read_text(encoding="utf-8")), p


def test_record_carries_degraded_reason_only_when_degraded():
    # 回帰（10/7 のライブ実行）: 劣化→壁時計切れの順で ABORTED になると、Governor に残った劣化理由が
    # RunRecord の検証に落ち、実行記録が1件も残らなかった。記録へは DEGRADED の時だけ載せる。
    from app.agent.run import record_degraded_reason
    from app.contracts import DegradedReason, RunStatus

    assert record_degraded_reason(RunStatus.ABORTED, DegradedReason.DENIAL_STREAK) is None
    assert record_degraded_reason(RunStatus.DEGRADED, DegradedReason.BUDGET) is DegradedReason.BUDGET
    assert record_degraded_reason(RunStatus.DONE, None) is None
