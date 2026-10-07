"""cloud_run_signature・run_check の窓口（registry）・G3 の差し込み口、そして取得→観測→チェッカー→判定表→RunRecord の通し。"""
import inspect

import pytest

import app.contracts as C
from app.adjudicate import adjudicate
from app.checks.autorun import autorun
from app.checks.cloud_run_signature import check_cloud_run_signature
from app.checks.contains_terms import check_contains_terms
from app.checks.http_probe import http_probe, observe_probe
from app.checks.leak_scan import check_leak_scan
from app.checks.registry import CHECKERS, CheckContext, pick_submission_doc, run_checker
from app.textsafe import BLOCK_SEP
from tests.factories import make_doc, make_record, make_verified, seal
from tests.fetch_fakes import (
    CLOUD_RUN_URL,
    HOST,
    LOGIN_URL,
    SUB_URL,
    FakeFetchPort,
    SleepRecorder,
    make_result,
    redirect,
    timeout_result,
)

GFE = {"content-type": "text/html", "server": "Google Frontend"}
LONG = "<p>" + "あ" * 600 + "</p>"


def req(check_class: C.CheckClass = C.CheckClass.RUNTIME_SIGNATURE, req_id: str = "R4"):
    return make_verified(req_id, check_class=check_class)


def probe(result, obs_id="O1", target="SUBMISSION_URL"):
    return observe_probe(result, obs_id=obs_id, target=target)


# ---------------------------------------------------------------------------
# cloud_run_signature
# ---------------------------------------------------------------------------
def test_signature_present_needs_the_service_domain_and_google_frontend_and_a_served_response():
    p = probe(make_result(CLOUD_RUN_URL, body=LONG, headers=GFE))
    o = check_cloud_run_signature(req(), [p], "O2")
    assert (o.tool, o.checker, o.req_id) == (C.ToolName.RUN_CHECK, C.Checker.CLOUD_RUN_SIGNATURE, "R4")
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.SIGNATURE_PRESENT, C.ObsOutcome.PASS, True)
    assert o.facts == {"target": "SUBMISSION_URL", "run_app_host": True, "gfe": True, "status": 200}
    assert "demo-submission" not in o.model_dump_json()


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        (CLOUD_RUN_URL, {"content-type": "text/html", "server": "nginx"}),  # ホストだけ
        (SUB_URL, GFE),  # Google Frontend だけ（独自ドメインの Cloud Run・App Engine 等と区別できない）
        (SUB_URL, {"content-type": "text/html"}),
    ],
)
def test_signature_absent_is_inconclusive_never_a_fail(url, headers):
    o = check_cloud_run_signature(req(), [probe(make_result(url, body=LONG, headers=headers))], "O2")
    assert (o.code, o.outcome, o.strong) == (C.ObsCode.SIGNATURE_ABSENT, C.ObsOutcome.INCONCLUSIVE, False)


@pytest.mark.parametrize("status", [404, 403, 500])
def test_google_frontend_error_pages_do_not_prove_a_running_service(status):
    """存在しないサービスの 404 や IAM の 403 も Google Frontend が返す。動いている証拠にしない。"""
    o = check_cloud_run_signature(req(), [probe(make_result(CLOUD_RUN_URL, status=status, body=b"", headers=GFE))], "O2")
    assert o.code is C.ObsCode.SIGNATURE_ABSENT and o.facts["status"] == status


def test_signature_holds_behind_a_login_wall_because_the_service_still_answers():
    r = make_result(CLOUD_RUN_URL, status=302, redirects=(redirect(frm=CLOUD_RUN_URL, location="/login", followed=False, blocked_policy=C.PolicyId.SCOPE),),
                    final_url=CLOUD_RUN_URL, body=b"", headers=GFE)  # fmt: skip
    assert check_cloud_run_signature(req(), [probe(r)], "O2").code is C.ObsCode.SIGNATURE_PRESENT


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (timeout_result(CLOUD_RUN_URL), C.ObsCode.TRANSIENT),
        (make_result(CLOUD_RUN_URL, outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.SCOPE, content_kind=None, headers={}), C.ObsCode.BLOCKED),
    ],
)
def test_signature_without_a_response_carries_the_probe_code(result, code):
    o = check_cloud_run_signature(req(), [probe(result)], "O2")
    assert (o.code, o.outcome) == (code, C.ObsOutcome.INCONCLUSIVE)


def test_signature_without_a_probe_is_an_inconclusive_error():
    o = check_cloud_run_signature(req(), [], "O2")
    assert (o.code, o.outcome) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE) and o.facts["reason"] == "no_probe"


# ---------------------------------------------------------------------------
# registry（run_check の窓口）
# ---------------------------------------------------------------------------
def test_registry_has_all_five_checkers():
    assert set(CHECKERS) == set(C.Checker)


def sub_doc(text: str = "あ" * 900, doc_id: str = "D3", **kw):
    return make_doc(doc_id, text, role=C.DocRole.SUBMISSION, url=SUB_URL, **kw)


def spec_len_req():
    spec = make_doc("D1", f"{'提出物の説明は800字以内とする。'}{BLOCK_SEP}締切は10月15日である。")
    return make_verified("R1", doc=spec, needle="提出物の説明は800字以内とする。", check_class=C.CheckClass.LENGTH_LIMIT)


def test_run_checker_text_length_uses_the_only_submission_document():
    ctx = CheckContext(docs={"D3": sub_doc()})
    o = run_checker(C.Checker.TEXT_LENGTH, spec_len_req(), ctx, "O1")
    assert (o.checker, o.doc_id, o.code) == (C.Checker.TEXT_LENGTH, "D3", C.ObsCode.OVER_LIMIT)


def test_run_checker_ignores_spec_documents_when_picking_the_submission():
    spec = make_doc("D1", "要項です")
    ctx = CheckContext(docs={"D1": spec, "D3": sub_doc()})
    assert pick_submission_doc(ctx)[0].doc_id == "D3"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("docs", "target", "why"),
    [
        ({}, None, "no_submission_doc"),
        ({"D1": make_doc("D1", "要項です")}, None, "no_submission_doc"),
        ({"D3": sub_doc(), "D4": sub_doc(doc_id="D4")}, None, "ambiguous_doc"),
        ({"D3": sub_doc()}, "D9", "no_such_doc"),
    ],
)
def test_run_checker_without_a_unique_target_document_is_an_inconclusive_error(docs, target, why):
    o = run_checker(C.Checker.TEXT_LENGTH, spec_len_req(), CheckContext(docs=docs, target_doc_id=target), "O1")
    assert (o.code, o.outcome, o.doc_id) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, None) and o.facts == {"why": why}


def test_run_checker_target_document_selects_among_several():
    ctx = CheckContext(docs={"D3": sub_doc("あ" * 10), "D4": sub_doc("あ" * 900, doc_id="D4")}, target_doc_id="D4")
    o = run_checker(C.Checker.TEXT_LENGTH, spec_len_req(), ctx, "O1")
    assert o.doc_id == "D4" and o.code is C.ObsCode.OVER_LIMIT


def test_run_checker_auth_wall_and_signature_read_the_stored_probes():
    p = probe(make_result(CLOUD_RUN_URL, body=LONG, headers=GFE))
    ctx = CheckContext(docs={}, probes=(p,))
    wall = run_checker(C.Checker.AUTH_WALL, req(C.CheckClass.AUTH_WALL, "R2"), ctx, "O2")
    assert (wall.checker, wall.req_id, wall.code) == (C.Checker.AUTH_WALL, "R2", C.ObsCode.NO_AUTH_WALL)
    sig = run_checker(C.Checker.CLOUD_RUN_SIGNATURE, req(), ctx, "O3")
    assert (sig.checker, sig.req_id, sig.code) == (C.Checker.CLOUD_RUN_SIGNATURE, "R4", C.ObsCode.SIGNATURE_PRESENT)


def test_checkers_do_no_io(monkeypatch):
    """チェッカーはネットワーク・LLM を使わない（費用 0）。conftest の遮断に加え、ソケット生成自体を失敗させて確かめる。"""
    import socket

    def boom(*a, **k):
        raise AssertionError("チェッカーがソケットを作った")

    monkeypatch.setattr(socket, "socket", boom)
    ctx = CheckContext(docs={"D3": sub_doc()}, probes=(probe(make_result(body=LONG)),))
    run_checker(C.Checker.TEXT_LENGTH, spec_len_req(), ctx, "O1")
    run_checker(C.Checker.AUTH_WALL, req(C.CheckClass.AUTH_WALL, "R2"), ctx, "O2")
    run_checker(C.Checker.CLOUD_RUN_SIGNATURE, req(), ctx, "O3")


# ---------------------------------------------------------------------------
# G3 の差し込み口（今回は実装しない。シグネチャだけ）
# ---------------------------------------------------------------------------
def test_g3_pieces_are_stubs_with_stable_signatures():
    r = req(C.CheckClass.LEAK, "R5")
    doc = sub_doc()
    # leak_scan は第3弾で実装した（tests/test_leak_scan.py）。残りの差し込み口は contains_terms と AUTORUN
    assert check_leak_scan(r, [doc], "O1").checker is C.Checker.LEAK_SCAN
    with pytest.raises(NotImplementedError):
        check_contains_terms(r, doc, "O1")
    with pytest.raises(NotImplementedError):
        run_checker(C.Checker.CONTAINS_TERMS, r, CheckContext(docs={"D3": doc}), "O1")
    assert list(inspect.signature(check_leak_scan).parameters) == ["req", "docs", "obs_id"]
    assert list(inspect.signature(check_contains_terms).parameters) == ["req", "doc", "obs_id"]
    assert inspect.iscoroutinefunction(autorun)
    assert list(inspect.signature(autorun).parameters) == ["requirements", "ctx", "fetch", "submission_url", "next_obs_id"]


async def test_autorun_stub_raises_until_g3():
    with pytest.raises(NotImplementedError):
        await autorun([], CheckContext(docs={}), FakeFetchPort(make_result()), submission_url=SUB_URL, next_obs_id=lambda: "O1")


# ---------------------------------------------------------------------------
# 通し: FetchPort のフェイク → http_probe → チェッカー → 判定表 → RunRecord（デモ② D1・D2、デモ① の自己監査）
# ---------------------------------------------------------------------------
SENT = {
    "len": "提出物の説明は800字以内とする。",
    "auth": "提出URLは審査員がログインなしで開けること。",
    "runtime": "提出物はCloud Run上で動作すること。",
}


async def test_demo_defect_walkthrough_fetch_to_run_record():
    spec = make_doc("D1", BLOCK_SEP.join(SENT.values()))
    description = sub_doc(("あ" * 100 + "。\n") * 11 + "い" * 19)  # D1: 1,130字前後
    reqs = [
        make_verified("R1", doc=spec, needle=SENT["len"], check_class=C.CheckClass.LENGTH_LIMIT),
        make_verified("R2", doc=spec, needle=SENT["auth"], check_class=C.CheckClass.AUTH_WALL),
        make_verified("R3", doc=spec, needle=SENT["runtime"], check_class=C.CheckClass.RUNTIME_SIGNATURE),
    ]
    login = make_result(
        redirects=(redirect(),), final_url=LOGIN_URL, body='<h1>ログイン</h1><form><input type="password" name="p"></form>',
        headers={"content-type": "text/html", "server": "Google Frontend"},
    )  # fmt: skip
    fetch = FakeFetchPort(login)

    # AUTORUN 相当: 提出URLを probe（1回）→ 要件ごとに run_check
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=SleepRecorder())
    ctx = CheckContext(docs={"D3": description}, probes=(res.observation,))
    o2 = run_checker(C.Checker.TEXT_LENGTH, reqs[0], ctx, "O2")
    o3 = run_checker(C.Checker.AUTH_WALL, reqs[1], ctx, "O3")
    o4 = run_checker(C.Checker.CLOUD_RUN_SIGNATURE, reqs[2], ctx, "O4")
    observations = (res.observation, o2, o3, o4)

    docs = (spec.meta(), description.meta())
    verdicts = adjudicate(C.AdjudicationInput(requirements=tuple(reqs), docs=docs, observations=observations))
    assert [v.label for v in verdicts] == [C.VerdictLabel.FAIL, C.VerdictLabel.FAIL, C.VerdictLabel.UNVERIFIABLE]
    assert verdicts[0].evidence[0].label.endswith("（上限800字）") and verdicts[0].evidence[0].label.startswith("1,1")
    assert verdicts[1].evidence[0].label == "302→/fx/defect/login/・password欄あり"  # ヒーローの証拠チップ
    assert verdicts[2].reason_code is C.UnverifiableReason.NO_EVIDENCE  # 署名が無い（ホストが予約ドメインでない）≠ Cloud Run でない

    rec = make_record(requirements=tuple(reqs), docs=docs, verdicts=verdicts, observations=observations)
    assert C.RunRecord.restore_json(C.serialize_report(rec), seal=seal()) == rec
    assert fetch.modes == [C.FetchMode.PROBE]


async def test_demo_self_audit_open_page_with_the_cloud_run_signature():
    """デモ①: 自サービスを http_probe → 200・認証なし・Cloud Run署名（強OBS）。"""
    spec = make_doc("D1", BLOCK_SEP.join(SENT.values()))
    reqs = [
        make_verified("R2", doc=spec, needle=SENT["auth"], check_class=C.CheckClass.AUTH_WALL),
        make_verified("R3", doc=spec, needle=SENT["runtime"], check_class=C.CheckClass.RUNTIME_SIGNATURE),
    ]
    fetch = FakeFetchPort(make_result(CLOUD_RUN_URL, body=LONG, headers=GFE))
    res = await http_probe(fetch, CLOUD_RUN_URL, obs_id="O1", sleep=SleepRecorder())
    ctx = CheckContext(docs={}, probes=(res.observation,))
    observations = (
        res.observation,
        run_checker(C.Checker.AUTH_WALL, reqs[0], ctx, "O2"),
        run_checker(C.Checker.CLOUD_RUN_SIGNATURE, reqs[1], ctx, "O3"),
    )
    verdicts = adjudicate(C.AdjudicationInput(requirements=tuple(reqs), docs=(spec.meta(),), observations=observations))
    assert [v.label for v in verdicts] == [C.VerdictLabel.PASS, C.VerdictLabel.PASS]
    assert verdicts[0].evidence[0].label == "200・ログイン不要で開ける"
    assert verdicts[1].evidence[0].label.startswith("Cloud Run署名あり") and "run.app" not in verdicts[1].evidence[0].label
    dumped = "".join(v.model_dump_json() for v in verdicts) + "".join(o.model_dump_json() for o in observations)
    assert "demo-submission" not in dumped and HOST not in dumped  # ホスト名はどこにも出ない（設計 §7 の別名化の前提）
