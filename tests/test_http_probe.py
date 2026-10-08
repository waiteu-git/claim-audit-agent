"""http_probe: 各観測（誰が開けるか）の取り違えがないこと・再試行・例外の扱い・facts に載せてよいものだけ。"""
import asyncio

import pytest

import app.contracts as C
from app.checks.http_probe import ProbeResult, http_probe, is_transient, observe_probe
from app.checks.probe_facts import TARGET_SUBMISSION, Access
from app.config import FETCH_LIMITS
from app.errors import AppError, ErrorCode
from tests.fetch_fakes import (
    CLOUD_RUN_URL,
    HOST,
    LOGIN_URL,
    SUB_URL,
    FakeFetchPort,
    SleepRecorder,
    make_result,
    network_error_result,
    redirect,
    timeout_result,
)

LONG = "<p>" + "あ" * 600 + "</p>"  # 内容のあるページ（短いログイン画面や SPA の殻と区別できる長さ）
PW_PAGE = '<h1>ログイン</h1><form action="/session" method="post"><input type="text" name="u"><input type="password" name="p"></form>'


def obs_of(result, **kw):
    return observe_probe(result, obs_id="O1", **kw)


def shape(o):
    return (o.code, o.outcome, o.strong, o.facts["access"])


# ---------------------------------------------------------------------------
# 誰が開けるか: 合格（開ける）
# ---------------------------------------------------------------------------
def test_open_page_is_a_strong_pass_with_status_and_no_wall_signals():
    o = obs_of(make_result(body=LONG))
    assert shape(o) == (C.ObsCode.NO_AUTH_WALL, C.ObsOutcome.PASS, True, "public")
    assert o.tool is C.ToolName.HTTP_PROBE and o.checker is None and o.req_id is None and o.doc_id is None
    f = o.facts
    assert f["status"] == 200 and f["has_password_input"] is False and f["spa_shell"] is False
    assert f["target"] == TARGET_SUBMISSION and f["outcome"] == "ok" and f["attempts"] == 1


def test_json_and_plain_responses_are_open_without_body_analysis():
    body = b'{"note": "<input type=\\"password\\">"}'  # 本文に password 欄らしい文字列があっても HTML ではない
    r = make_result(body=body, headers={"content-type": "application/json"}, content_kind=C.ContentKind.JSON)
    o = obs_of(r)
    assert o.code is C.ObsCode.NO_AUTH_WALL and "has_password_input" not in o.facts


def test_html_is_recognised_from_the_header_when_content_kind_is_unknown():
    r = make_result(body=PW_PAGE, content_kind=None)
    assert obs_of(r).code is C.ObsCode.AUTH_WALL


def test_no_content_response_is_open():
    assert obs_of(make_result(status=204, body=b"", headers={})).code is C.ObsCode.NO_AUTH_WALL


def test_a_short_static_page_with_an_analytics_script_is_not_called_a_spa():
    o = obs_of(make_result(body="<body><p>準備中です</p><script>ga('send')</script></body>"))
    assert shape(o) == (C.ObsCode.NO_AUTH_WALL, C.ObsOutcome.PASS, True, "public")


# ---------------------------------------------------------------------------
# 誰が開けるか: 認証壁（ログインへの転送・IdP・401/403・password 欄）
# ---------------------------------------------------------------------------
def test_demo_defect_d2_302_to_login_with_a_password_field():
    """デモ② D2: 提出URLが 302→/login（password欄あり）。ヒーローの証拠チップの材料が facts に揃う。"""
    r = make_result(
        redirects=(redirect(),), final_url=LOGIN_URL, body=PW_PAGE, status=200,
        headers={"content-type": "text/html", "server": "Google Frontend"},
    )  # fmt: skip
    o = obs_of(r)
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_redirect")
    f = o.facts
    assert f["redirect_hops"] == 1 and f["redirect_status"] == 302 and f["location_path"] == "/fx/defect/login/"
    assert f["has_password_input"] is True and f["status"] == 200


def test_login_redirect_that_was_not_followed_is_still_a_wall():
    """転送先がスコープ外（追跡しない）でも、Location がログイン用パスなら認証壁の証拠（§5-3）。"""
    hop = redirect(location="/login", followed=False, blocked_policy=C.PolicyId.SCOPE)
    o = obs_of(make_result(status=302, redirects=(hop,), final_url=SUB_URL, body=b""))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_redirect")
    assert o.facts["unfollowed"] is True and o.facts["location_path"] == "/login"
    assert "has_password_input" not in o.facts  # 追跡していないので本文は無い


def test_idp_redirect_is_a_wall_and_never_records_the_idp_host():
    hop = redirect(
        location="https://accounts.example.invalid/o/oauth2/auth?client_id=abc&redirect_uri=https://svc.example.invalid/cb",
        followed=False, blocked_policy=C.PolicyId.SCOPE,
    )  # fmt: skip
    o = obs_of(make_result(status=302, redirects=(hop,), final_url=SUB_URL, body=b""))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "idp_redirect")
    dumped = o.model_dump_json()
    assert "accounts.example" not in dumped and "client_id" not in dumped and "abc" not in dumped


def test_login_evidence_in_a_followed_chain_wins_over_a_login_page_that_renders_fine():
    """ログイン画面が JS 描画で password 欄が見えなくても、転送の連なりに /login があれば壁。"""
    r = make_result(redirects=(redirect(location="/login"),), final_url=LOGIN_URL, body='<div id="root"></div><script src="/a.js"></script>')
    assert shape(obs_of(r)) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_redirect")


def test_multi_hop_chain_reports_the_login_hop_not_the_first_hop():
    hops = (redirect(location="/start"), redirect(frm=f"https://{HOST}/start", location="/signin?next=/"))
    o = obs_of(make_result(redirects=hops, final_url=f"https://{HOST}/signin", body=PW_PAGE))
    assert o.facts["location_path"] == "/signin" and o.facts["redirect_hops"] == 2 and o.facts["redirect_status"] == 302


def test_unfollowed_redirect_to_an_ordinary_other_host_is_inconclusive_not_a_wall():
    hop = redirect(location="https://www.example.invalid/", followed=False, blocked_policy=C.PolicyId.SCOPE)
    o = obs_of(make_result(status=301, redirects=(hop,), final_url=SUB_URL, body=b""))
    assert shape(o) == (C.ObsCode.BLOCKED, C.ObsOutcome.INCONCLUSIVE, False, "unknown_redirect")
    assert o.facts["unfollowed"] is True


def test_401_is_a_strong_wall_and_403_is_a_wall_only_on_a_cloud_run_domain():
    o401 = obs_of(make_result(status=401, headers={"www-authenticate": 'Basic realm="x"'}, body=b""))
    assert shape(o401) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "http_401")
    o403 = obs_of(make_result(status=403, body=b""))
    assert shape(o403) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.INCONCLUSIVE, False, "http_403")  # WAF の拒否と区別できない
    iam = obs_of(make_result(CLOUD_RUN_URL, status=403, body=b"", headers={"content-type": "text/html", "server": "Google Frontend"}))
    assert shape(iam) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "http_403")  # Cloud Run の IAM の壁


def test_login_screen_with_a_password_field_is_a_wall_even_without_redirect():
    o = obs_of(make_result(body=PW_PAGE))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_form")
    assert o.facts["has_password_input"] is True and o.facts["text_len"] < 200


def test_password_field_on_a_content_rich_page_is_not_called_a_wall():
    body = f'<header><form><input type="password" name="p"></form></header>{LONG * 4}'
    o = obs_of(make_result(body=body))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.INCONCLUSIVE, False, "form_on_content")
    assert o.facts["has_password_input"] is True and o.facts["text_len"] > 1500


def test_search_form_page_is_open_not_a_wall():
    o = obs_of(make_result(body='<h1>検索</h1><form action="/search"><input type="search" name="q"></form>'))
    assert shape(o) == (C.ObsCode.NO_AUTH_WALL, C.ObsOutcome.PASS, True, "public")
    assert o.facts["has_password_input"] is False


def test_meta_refresh_to_a_login_path_is_a_wall():
    o = obs_of(make_result(body='<meta http-equiv="refresh" content="0; url=/login">'))
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_redirect")
    assert o.facts["redirect_status"] == 0 and o.facts["location_path"] == "/login"


def test_spa_shell_is_inconclusive_needing_js():
    o = obs_of(make_result(body='<body><div id="root"></div><script src="/static/app.js"></script></body>'))
    assert shape(o) == (C.ObsCode.SPA_SHELL, C.ObsOutcome.INCONCLUSIVE, False, "spa_shell")
    assert o.facts["spa_shell"] is True


# ---------------------------------------------------------------------------
# 取得の結末: 一時的な失敗・拒否・種別・サイズ・転送上限・HTTP エラー
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("res", [timeout_result(), network_error_result()])
def test_timeouts_and_connection_failures_are_transient(res):
    assert shape(obs_of(res)) == (C.ObsCode.TRANSIENT, C.ObsOutcome.INCONCLUSIVE, False, "unreachable")


@pytest.mark.parametrize("status", [429, 503, 502, 504])
def test_infrastructure_errors_without_the_app_header_are_transient_never_a_fail(status):
    o = obs_of(make_result(status=status, headers={}, body=b""))
    assert shape(o) == (C.ObsCode.TRANSIENT, C.ObsOutcome.INCONCLUSIVE, False, "unreachable")


def test_503_with_the_app_header_is_the_apps_own_answer_not_transient():
    o = obs_of(make_result(status=503, headers={"x-audit-app": "1"}, body=b""))
    assert shape(o) == (C.ObsCode.ERROR, C.ObsOutcome.FAIL, False, "http_error")
    assert not is_transient(make_result(status=503, headers={"x-audit-app": "1"}, body=b""))
    assert is_transient(make_result(status=502, headers={"x-audit-app": "1"}, body=b""))  # ゲートウェイ系は常に一時的


def test_404_is_a_strong_fail_500_a_weak_fail_other_4xx_inconclusive():
    assert shape(obs_of(make_result(status=404, body=b""))) == (C.ObsCode.ERROR, C.ObsOutcome.FAIL, True, "not_found")
    assert shape(obs_of(make_result(status=410, body=b""))) == (C.ObsCode.ERROR, C.ObsOutcome.FAIL, True, "not_found")
    assert shape(obs_of(make_result(status=500, body=b""))) == (C.ObsCode.ERROR, C.ObsOutcome.FAIL, False, "http_error")
    assert shape(obs_of(make_result(status=400, body=b""))) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "http_error")
    assert shape(obs_of(make_result(status=405, body=b""))) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "http_error")


def test_blocked_fetch_records_the_policy_only():
    r = make_result(outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.SCOPE, content_kind=None, headers={})
    o = obs_of(r)
    assert shape(o) == (C.ObsCode.BLOCKED, C.ObsOutcome.INCONCLUSIVE, False, "blocked")
    assert o.facts["policy"] == "P-SCOPE-01" and "run_app_host" not in o.facts
    r2 = make_result(outcome=C.FetchOutcome.BLOCKED, blocked_policy=C.PolicyId.SSRF_IP, content_kind=None, headers={})
    assert obs_of(r2).facts["policy"] == "P-SSRF-IP-01"


def test_unsupported_type_too_large_and_redirect_limit_are_inconclusive_with_distinct_access():
    ut = make_result(outcome=C.FetchOutcome.UNSUPPORTED_TYPE, status=200, headers={"content-type": "application/pdf"}, content_kind=C.ContentKind.UNSUPPORTED)
    assert shape(obs_of(ut)) == (C.ObsCode.UNSUPPORTED_TYPE, C.ObsOutcome.INCONCLUSIVE, False, "unsupported_type")
    big = make_result(outcome=C.FetchOutcome.TOO_LARGE, limit_hit=C.FetchLimit.CONTENT_LENGTH, content_kind=None)
    assert shape(obs_of(big)) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "too_large")
    hops = tuple(redirect(frm=f"https://{HOST}/{i}", location=f"/{i + 1}") for i in range(3)) + (
        redirect(frm=f"https://{HOST}/3", location="/4", followed=False),
    )
    many = make_result(outcome=C.FetchOutcome.TOO_MANY_REDIRECTS, limit_hit=C.FetchLimit.REDIRECTS, redirects=hops, status=302)
    assert shape(obs_of(many)) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "redirect_limit")


def test_login_evidence_before_a_redirect_limit_is_still_a_wall():
    hops = (
        redirect(frm=f"https://{HOST}/a", location="/b"),
        redirect(frm=f"https://{HOST}/b", location="/login"),
        redirect(frm=f"https://{HOST}/login", location="/login2"),
        redirect(frm=f"https://{HOST}/login2", location="/login3", followed=False),
    )
    many = make_result(outcome=C.FetchOutcome.TOO_MANY_REDIRECTS, limit_hit=C.FetchLimit.REDIRECTS, redirects=hops, status=302)
    o = obs_of(many)
    assert shape(o) == (C.ObsCode.AUTH_WALL, C.ObsOutcome.FAIL, True, "login_redirect") and o.facts["location_path"] == "/login"


def test_timeout_after_a_login_redirect_is_still_a_wall_and_not_transient():
    """/login へ転送された後でログイン画面の取得が時間切れ。転送の事実は残るので、一時的な失敗扱いにして洗浄しない。"""
    r = make_result(outcome=C.FetchOutcome.TIMEOUT, limit_hit=C.FetchLimit.TOTAL_TIMEOUT, redirects=(redirect(location="/login"),), content_kind=None, headers={})
    assert obs_of(r).code is C.ObsCode.AUTH_WALL and not is_transient(r)


def test_informational_status_is_not_misread_as_open():
    assert obs_of(make_result(status=103, body=b"")).code is C.ObsCode.ERROR


def test_redirect_without_hops_is_unexpected_not_a_pass():
    o = obs_of(make_result(status=304, body=b""))
    assert shape(o) == (C.ObsCode.ERROR, C.ObsOutcome.INCONCLUSIVE, False, "unexpected")


# ---------------------------------------------------------------------------
# Cloud Run 署名の材料と facts の安全性
# ---------------------------------------------------------------------------
def test_cloud_run_signature_markers_are_booleans_and_the_host_is_never_recorded():
    r = make_result(CLOUD_RUN_URL, body=LONG, headers={"content-type": "text/html", "server": "Google Frontend"})
    o = obs_of(r)
    assert o.facts["run_app_host"] is True and o.facts["gfe"] is True
    assert "demo-submission" not in o.model_dump_json() and "run.app" not in o.model_dump_json()


@pytest.mark.parametrize(
    ("url", "server", "host_sig", "gfe"),
    [
        (CLOUD_RUN_URL, "nginx", True, False),
        (SUB_URL, "Google Frontend", False, True),
        (SUB_URL, "nginx", False, False),
        ("https://" + "x" + "." + "run" + ".app.example.invalid/", "Google Frontend", False, True),  # 接尾辞の偽装は host ではない
    ],
)
def test_signature_markers_are_independent(url, server, host_sig, gfe):
    o = obs_of(make_result(url, body=LONG, headers={"content-type": "text/html", "server": server}))
    assert (o.facts["run_app_host"], o.facts["gfe"]) == (host_sig, gfe)


def test_final_host_after_a_followed_redirect_decides_the_host_marker():
    hop = redirect(frm=SUB_URL, location=CLOUD_RUN_URL, in_scope=True)
    o = obs_of(make_result(redirects=(hop,), final_url=CLOUD_RUN_URL, body=LONG, headers={"content-type": "text/html", "server": "Google Frontend"}))
    assert o.facts["run_app_host"] is True


def test_every_fact_is_a_short_identifier_a_number_or_a_flag():
    cases = [
        make_result(body=LONG),
        make_result(redirects=(redirect(),), final_url=LOGIN_URL, body=PW_PAGE),
        make_result(redirects=(redirect(location="https://idp.example.invalid/login?x=https://a.example.invalid/"),), final_url=LOGIN_URL, body=PW_PAGE),
        timeout_result(),
        make_result(status=404, body=b""),
    ]
    for r in cases:
        o = obs_of(r)
        assert len(o.facts) <= 16
        for k, v in o.facts.items():
            assert isinstance(v, (bool, int, str))
            if isinstance(v, str):
                assert len(v) <= 64 and "//" not in v and "http" not in v and "?" not in v, (k, v)


def test_hostile_location_values_cannot_break_the_observation():
    for loc in ("/ログイン", "/" + "a" * 500, "/login?next=https://evil.example.invalid/", "//evil.example.invalid/login", "/a b\u0000c"):
        hop = redirect(location=loc, followed=False, blocked_policy=C.PolicyId.SCOPE)
        o = obs_of(make_result(status=302, redirects=(hop,), final_url=SUB_URL, body=b""))
        assert isinstance(o, C.Observation)  # facts の制約（URL・長さ・文字種）で ValidationError にならない
        assert "evil" not in o.model_dump_json()


def test_observation_carries_no_page_text():
    r = make_result(body='<h1>ひみつ</h1><p>ひみつの本文ABC</p><input type="password">')
    dumped = obs_of(r).model_dump_json()
    assert "ひみつ" not in dumped and "ABC" not in dumped


def test_strong_is_never_set_on_an_inconclusive_observation():
    results = [timeout_result(), make_result(status=503, headers={}), make_result(body='<div id="root"></div><script src="a.js"></script>')]
    for r in results:
        o = obs_of(r)
        assert o.outcome is C.ObsOutcome.INCONCLUSIVE and o.strong is False


# ---------------------------------------------------------------------------
# http_probe 本体: FetchPort を probe モードで呼ぶ・再試行（S-04）・例外
# ---------------------------------------------------------------------------
async def test_probe_requests_probe_mode_once_and_returns_the_observation():
    fetch = FakeFetchPort(make_result(body=LONG))
    sleep = SleepRecorder()
    res = await http_probe(fetch, SUB_URL, obs_id="O7", sleep=sleep)
    assert isinstance(res, ProbeResult) and res.attempts == 1 and res.access is Access.PUBLIC
    assert fetch.modes == [C.FetchMode.PROBE] and fetch.calls[0].url == SUB_URL
    assert res.observation.obs_id == "O7" and res.observation.code is C.ObsCode.NO_AUTH_WALL
    assert sleep.delays == []  # 成功時は待たない


async def test_probe_target_is_recorded_for_the_checkers_to_select():
    res = await http_probe(FakeFetchPort(make_result(body=LONG)), SUB_URL, obs_id="O1", target="L3", sleep=SleepRecorder())
    assert res.observation.facts["target"] == "L3"


async def test_transient_failure_is_retried_once_after_two_seconds():
    fetch = FakeFetchPort(make_result(status=503, headers={}, body=b""), make_result(body=LONG))
    sleep = SleepRecorder()
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=sleep)
    assert len(fetch.calls) == 2 and res.attempts == 2 and sleep.delays == [FETCH_LIMITS.probe_retry_delay_s] == [2.0]
    assert res.observation.code is C.ObsCode.NO_AUTH_WALL and res.observation.facts["attempts"] == 2


async def test_still_transient_after_the_one_retry_is_inconclusive_not_a_fail():
    fetch = FakeFetchPort(timeout_result(), timeout_result(), timeout_result())
    sleep = SleepRecorder()
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=sleep)
    assert len(fetch.calls) == 1 + FETCH_LIMITS.probe_retry_max == 2 and sleep.delays == [2.0]
    assert (res.observation.code, res.observation.outcome) == (C.ObsCode.TRANSIENT, C.ObsOutcome.INCONCLUSIVE)
    assert res.access is Access.UNREACHABLE and res.attempts == 2


@pytest.mark.parametrize(
    "result",
    [
        make_result(status=404, body=b""),
        make_result(status=401, body=b""),
        make_result(redirects=(redirect(),), final_url=LOGIN_URL, body=PW_PAGE),
        make_result(status=503, headers={"x-audit-app": "1"}, body=b""),
        make_result(body=LONG),
    ],
)
async def test_conclusive_results_are_not_retried(result):
    fetch = FakeFetchPort(result)
    sleep = SleepRecorder()
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=sleep)
    assert res.attempts == 1 and len(fetch.calls) == 1 and sleep.delays == []


async def test_a_retry_that_finds_a_wall_reports_the_wall():
    fetch = FakeFetchPort(network_error_result(), make_result(redirects=(redirect(),), final_url=LOGIN_URL, body=PW_PAGE))
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=SleepRecorder())
    assert res.observation.code is C.ObsCode.AUTH_WALL and res.attempts == 2


async def test_fetch_blocked_error_becomes_a_blocked_observation_without_retry():
    fetch = FakeFetchPort(AppError(ErrorCode.FETCH_BLOCKED, "scope"))
    sleep = SleepRecorder()
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=sleep)
    assert res.access is Access.BLOCKED and res.observation.code is C.ObsCode.BLOCKED
    assert res.attempts == 1 and sleep.delays == []
    assert "scope" not in res.observation.model_dump_json()  # 例外の文面（str(e)）は観測に載せない


@pytest.mark.parametrize("exc", [AppError(ErrorCode.RETRYABLE, "x"), ConnectionError("reset"), TimeoutError()])
async def test_retryable_exceptions_are_treated_like_transient_results(exc):
    fetch = FakeFetchPort(exc, make_result(body=LONG))
    res = await http_probe(fetch, SUB_URL, obs_id="O1", sleep=SleepRecorder())
    assert res.observation.code is C.ObsCode.NO_AUTH_WALL and res.attempts == 2
    always = FakeFetchPort(exc)
    res2 = await http_probe(always, SUB_URL, obs_id="O1", sleep=SleepRecorder())
    assert res2.observation.code is C.ObsCode.TRANSIENT and res2.attempts == 2


async def test_unknown_errors_and_cancellation_propagate():
    with pytest.raises(AppError):
        await http_probe(FakeFetchPort(AppError(ErrorCode.INTERNAL, "boom")), SUB_URL, obs_id="O1", sleep=SleepRecorder())
    with pytest.raises(ValueError):
        await http_probe(FakeFetchPort(ValueError("x")), SUB_URL, obs_id="O1", sleep=SleepRecorder())
    with pytest.raises(asyncio.CancelledError):  # 切断・壁時計超過の中止を呑み込まない
        await http_probe(FakeFetchPort(asyncio.CancelledError()), SUB_URL, obs_id="O1", sleep=SleepRecorder())


def test_fake_fetch_port_satisfies_the_fetch_port_protocol():
    assert isinstance(FakeFetchPort(make_result()), C.FetchPort)


async def test_target_must_be_the_submission_constant_or_a_link_id():
    for bad in ("https://svc.example.invalid/", "submission_url", "L", "L1234", "L1; drop", ""):
        with pytest.raises(ValueError):
            observe_probe(make_result(body=LONG), obs_id="O1", target=bad)
        with pytest.raises(ValueError):
            await http_probe(FakeFetchPort(make_result()), SUB_URL, obs_id="O1", target=bad, sleep=SleepRecorder())
    assert observe_probe(make_result(body=LONG), obs_id="O1", target="L12").facts["target"] == "L12"
