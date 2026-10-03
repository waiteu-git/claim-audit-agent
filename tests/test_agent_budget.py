"""budget.py: 予約→精算・壁時計・件数上限。"""
import asyncio

from app.agent.budget import BudgetMeter, apply_requirement_caps, estimate_tokens, requirement_cap
from app.config import RUN_CAPS
from app.contracts import Kind, ModelPurpose, Usage
from tests.agent_support import FakeClock, raw

R, P = ModelPurpose.READER, ModelPurpose.PLANNER


def test_estimate_tokens_is_pessimistic_for_japanese_and_cheaper_for_ascii():
    assert estimate_tokens("") == 0
    assert estimate_tokens("あいう") == 3
    assert estimate_tokens("abcdef") == 2
    assert estimate_tokens("あa") == 2  # 切り上げ


def test_reservation_charges_worst_case_then_settles_to_the_actual_usage():
    m = BudgetMeter(RUN_CAPS)
    res = m.reserve_model(R, 1000, 4096)
    assert res is not None and (m.budget.tokens_in, m.budget.tokens_out, m.budget.reader_calls) == (1000, 4096, 1)
    m.settle_model(res, Usage(prompt_tokens=900, candidates_tokens=300, thoughts_tokens=100))
    assert (m.budget.tokens_in, m.budget.tokens_out) == (900, 400)


def test_actual_usage_above_the_estimate_is_charged_too():
    m = BudgetMeter(RUN_CAPS)
    res = m.reserve_model(R, 100, 100)
    m.settle_model(res, Usage(prompt_tokens=5000, candidates_tokens=900))
    assert (m.budget.tokens_in, m.budget.tokens_out) == (5000, 900)


def test_a_call_that_returns_no_usage_keeps_the_worst_case():
    m = BudgetMeter(RUN_CAPS)
    res = m.reserve_model(R, 1000, 4096)
    m.settle_model(res, None)  # 切断・タイムアウト
    assert (m.budget.tokens_in, m.budget.tokens_out) == (1000, 4096)


def test_reserve_refuses_without_charging_when_a_limit_would_be_crossed():
    m = BudgetMeter(RUN_CAPS)
    assert m.reserve_model(R, RUN_CAPS.tokens_in + 1, 10) is None
    assert m.reserve_model(R, 10, RUN_CAPS.tokens_out + 1) is None
    assert (m.budget.tokens_in, m.budget.tokens_out, m.budget.model_calls) == (0, 0, 0)
    assert m.reserve_model(R, RUN_CAPS.tokens_in, RUN_CAPS.tokens_out) is not None  # ちょうど上限は通る
    assert m.reserve_model(R, 1, 0) is None


def test_reserved_calls_count_immediately_so_parallel_calls_cannot_exceed_the_cap():
    caps = RUN_CAPS.model_copy(update={"model_calls_reader": 2, "model_calls_planner": 1, "model_calls_spare": 0})
    m = BudgetMeter(caps)
    held = [m.reserve_model(R, 10, 10) for _ in range(5)]  # どれも精算前に予約だけ
    assert [h is not None for h in held] == [True, True, False, False, False]
    assert m.reserve_model(P, 10, 10) is not None  # Planner の専用枠は別


def test_spare_calls_are_shared_between_reader_and_planner():
    caps = RUN_CAPS.model_copy(update={"model_calls_reader": 1, "model_calls_planner": 1, "model_calls_spare": 1})
    m = BudgetMeter(caps)
    assert [m.reserve_model(R, 1, 1) is not None for _ in range(3)] == [True, True, False]
    assert m.reserve_model(P, 1, 1) is not None
    assert m.reserve_model(P, 1, 1) is None


def test_wall_clock_comes_from_the_injected_clock_and_blocks_new_reservations():
    clock = FakeClock()
    m = BudgetMeter(RUN_CAPS, clock)
    assert not m.wall_expired()
    clock.advance(RUN_CAPS.wall_clock_s - 0.001)
    assert not m.wall_expired() and m.reserve_model(R, 1, 1) is not None
    clock.advance(0.002)
    assert m.wall_expired() and m.reserve_model(R, 1, 1) is None
    assert m.budget.snapshot().wall_ms_left == 0


def test_elapsed_never_goes_backwards():
    clock = FakeClock()
    m = BudgetMeter(RUN_CAPS, clock)
    clock.advance(10)
    assert m.tick() == 10_000
    clock.advance(-5)
    assert m.tick() == 10_000


def test_requirement_caps_per_kind_with_obligatory_kinds_sharing_one_cap():
    caps = RUN_CAPS.model_copy(
        update={"requirements_obligatory": 3, "requirements_speculative": 1, "requirements_optional": 1, "requirements_request": 1}
    )
    raws = [raw(f"項目{i}は必須とすること。", Kind.REQUIRED if i % 2 else Kind.PROHIBITED) for i in range(6)]
    raws += [raw("推測A", Kind.SPECULATIVE), raw("推測B", Kind.SPECULATIVE), raw("任意A", Kind.OPTIONAL), raw("任意B", Kind.OPTIONAL)]
    raws += [raw("依頼A", Kind.REQUEST), raw("依頼B", Kind.REQUEST)]
    kept, dropped = apply_requirement_caps(raws, caps)
    assert [r.quote for r in kept] == ["項目0は必須とすること。", "項目1は必須とすること。", "項目2は必須とすること。", "推測A", "任意A", "依頼A"]
    assert dropped == len(raws) - len(kept) == 6
    assert requirement_cap(RUN_CAPS, Kind.REQUIRED) == requirement_cap(RUN_CAPS, Kind.PROHIBITED) == 64
    assert requirement_cap(RUN_CAPS, Kind.SPECULATIVE) == 8


def test_no_event_loop_is_needed():
    assert asyncio.iscoroutinefunction(BudgetMeter.reserve_model) is False
