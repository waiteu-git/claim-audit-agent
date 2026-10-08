"""WallBoundPort（モデル呼び出しを壁時計の内側に収める）と、web の外側の期限の計算。

背景（10/8 の敵対レビュー）: 壁時計は協調式で、実行中の呼び出しは打ち切らない。応答の遅い時間帯に、上限の直前に始めた呼び出しが
外側の期限より後まで続くと、費用が分からず予約の最悪値で精算される。呼び出しを壁時計の内側に収めて、協調式の中断を先に起こす。
"""
import asyncio
import time

import pytest

from app.config import RUN_CAPS
from app.contracts import ModelPurpose, ModelRequest, ModelResponse, Usage
from app.errors import AppError, ErrorCode, classify
from app.model.wallbound import WallBoundPort
from app.web.app import CLOUD_RUN_TIMEOUT_S, SWITCH_REPLAY_DELAY_S, SWITCH_RESERVE_S, bound_model, run_budget_s
from tests.web_support import make_deps

REQ = ModelRequest(purpose=ModelPurpose.READER, system="s", contents="c", max_output_tokens=16, timeout_s=25.0)
OK = ModelResponse(model="inner-model", text="{}", usage=Usage(prompt_tokens=1, candidates_tokens=1))


class Inner:
    model_id = "inner-model"

    def __init__(self, delay_s: float = 0.0, error: Exception | None = None) -> None:
        self.delay_s, self.error, self.calls = delay_s, error, 0

    async def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        if self.error is not None:
            raise self.error
        return OK


def run(coro):
    return asyncio.run(coro)


def test_a_call_that_finishes_before_the_deadline_returns_its_response():
    port = WallBoundPort(Inner(0.01), deadline_monotonic=time.monotonic() + 5)
    assert run(port.generate(REQ)) is OK and port.model_id == "inner-model"


def test_a_call_still_running_at_the_deadline_plus_slack_is_cut_and_classified_as_retryable():
    inner = Inner(5.0)
    port = WallBoundPort(inner, deadline_monotonic=time.monotonic() + 0.05, slack_s=0.05)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError) as e:
        run(port.generate(REQ))
    assert time.monotonic() - t0 < 1.0  # 5 秒待たずに打ち切る
    assert classify(e.value) is ErrorCode.RETRYABLE


def test_no_call_is_started_after_the_deadline_plus_slack():
    inner = Inner()
    port = WallBoundPort(inner, deadline_monotonic=time.monotonic() - 10, slack_s=1.0)
    with pytest.raises(TimeoutError):
        run(port.generate(REQ))
    assert inner.calls == 0  # 始めない＝費用もかからない


def test_an_error_from_the_inner_port_passes_through_unchanged():
    err = AppError(ErrorCode.FATAL_CONFIG, "x")
    port = WallBoundPort(Inner(error=err), deadline_monotonic=time.monotonic() + 5)
    with pytest.raises(AppError) as e:
        run(port.generate(REQ))
    assert e.value is err


def test_cancellation_is_not_swallowed():
    async def go():
        port = WallBoundPort(Inner(5.0), deadline_monotonic=time.monotonic() + 30)
        task = asyncio.ensure_future(port.generate(REQ))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(go())


def test_the_slack_must_not_be_negative():
    with pytest.raises(ValueError):
        WallBoundPort(Inner(), deadline_monotonic=0.0, slack_s=-1)


def test_the_production_composition_bounds_a_hung_call_and_stops_retrying_at_the_deadline():
    hung = Inner(5.0)
    port = bound_model(hung, deadline_monotonic=time.monotonic() + 0.05)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        run(port.generate(REQ))
    assert time.monotonic() - t0 < 3.0 and hung.calls == 1  # 締切＋余裕（2秒）で打ち切り、再試行もしない
    flaky = Inner(error=AppError(ErrorCode.RETRYABLE, "429"))
    port = bound_model(flaky, deadline_monotonic=time.monotonic() + 0.01)
    t0 = time.monotonic()
    with pytest.raises(AppError):
        run(port.generate(REQ))
    assert flaky.calls == 1 and time.monotonic() - t0 < 0.9  # 1秒のバックオフを待たない（締切の内側に収まらない再試行はしない）


# ---- 外側の期限 ---------------------------------------------------------------------------------
def test_the_outer_deadline_leaves_room_for_the_switch_inside_the_cloud_run_timeout():
    deps = make_deps()
    budget = run_budget_s(deps, 1000.0, 1000.0)
    assert budget == CLOUD_RUN_TIMEOUT_S - SWITCH_RESERVE_S == 108.0 and deps.run_timeout_s == 110.0  # 受付の直後は、Cloud Run 側の計算が効く
    biggest = max(len(b.event_jsons) for b in deps.replays.values())
    replay_s = biggest * SWITCH_REPLAY_DELAY_S
    assert budget + replay_s + 5.0 <= CLOUD_RUN_TIMEOUT_S  # 切り替えの再生と、精算・通信の余裕（5秒）が、timeout の内側に入る
    assert budget > RUN_CAPS.wall_clock_s  # 協調式の中断（壁時計）が先に起きるように、外側は壁時計より後ろ


def test_time_already_spent_before_the_run_started_is_taken_off_the_outer_deadline():
    deps = make_deps()
    assert run_budget_s(deps, 0.0, 4.0) == 104.0  # 受付から4秒（ADMIT・Firestore の往復）を引く
    assert run_budget_s(deps, 0.0, 200.0) == 1.0  # 取り返しがつかないほど経っていても、負や 0 にしない
    deps.run_timeout_s = 0.05
    assert run_budget_s(deps, 0.0, 0.0) == 0.05  # 設定で短くした期限（テスト）は、そのまま効く
