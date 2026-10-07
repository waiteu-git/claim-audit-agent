"""quota.py: 予約→精算・期限切れの掃除・日次/累計の円上限・匿名枠（全体で1日4回）・審査員枠・二重ラッチ・ADMIT ゲート・fail-closed。
state_firestore.py: Firestore 実装のトランザクションの組み立て（フェイクのクライアントで。実接続はしない）。"""
import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.config import QUOTA_POLICY, RESERVATION_MICRO_JPY, Settings
from app.contracts import EnvName
from app.quota import (
    AdmitRejected,
    InMemoryState,
    Pool,
    QuotaService,
    ReplayReason,
    StatePort,
    code_digest,
    judge_code_matches,
    usage_from_trace,
)
from app.state_firestore import FirestoreState

JUDGE = "judge-code-for-tests"


class Now:
    def __init__(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw) -> None:
        self.t += timedelta(**kw)


class Mono:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        self.t += 2.0  # ADMIT ゲート（1試行/秒）に当たらない
        return self.t


def svc(*, live=True, kill=False, store=None, policy=QUOTA_POLICY, now=None, judge=(JUDGE,), env=EnvName.DEV):
    s = Settings(live_enabled=live, kill_switch=kill, judge_code_sha256=tuple(code_digest(j) for j in judge), env=env)
    return QuotaService(s, store or InMemoryState(), policy=policy, now=now or Now(datetime(2026, 10, 10, 0, 30, tzinfo=UTC)),
                        monotonic=Mono())  # fmt: skip


def run(coro):
    return asyncio.run(coro)


# ---- 二重ラッチ・ゲート・fail-closed -------------------------------------------------------------
def test_live_needs_both_latches_open():
    assert run(svc(live=False).admit()).replay_reason is ReplayReason.LIVE_DISABLED
    assert run(svc(kill=True).admit()).replay_reason is ReplayReason.KILLED
    assert run(svc().admit()).live


def test_the_stored_kill_live_flag_closes_live_and_is_cached_briefly():
    q = svc()
    run(q.trip_kill())
    assert run(q.admit()).replay_reason is ReplayReason.KILLED
    assert run(q.mode()) == "STOPPED"


def test_admit_gate_allows_one_attempt_per_second():
    q = svc()
    q._gate.clock = lambda: 5.0
    run(q.admit())
    with pytest.raises(AdmitRejected):
        run(q.admit())


def test_an_unreachable_store_is_fail_closed():
    store = InMemoryState()
    store.fail = True
    assert run(svc(store=store).admit()).replay_reason is ReplayReason.STORE_UNAVAILABLE
    assert run(svc(store=store).mode()) == "REPLAY"


def test_in_memory_state_satisfies_the_protocol_and_refuses_writes_to_unread_keys():
    s = InMemoryState()
    assert isinstance(s, StatePort)
    with pytest.raises(KeyError):
        run(s.transaction(["a"], lambda d: {"b": {"x": 1}}))


# ---- 匿名枠 ---------------------------------------------------------------------------------------
def test_anonymous_is_four_runs_a_day_one_per_six_hour_slot_with_no_per_user_key():
    now = Now(datetime(2026, 10, 9, 15, 30, tzinfo=UTC))  # JST 10/10 00:30
    q = svc(now=now)
    assert run(q.admit()).live
    assert run(q.admit()).replay_reason is ReplayReason.QUOTA  # 同じ枠（0〜6時）は1回
    for _ in range(3):
        now.advance(hours=6)
        assert run(q.admit()).live
    now.advance(hours=5)  # JST 23:30（18時の枠を使用済み）
    assert run(q.admit()).replay_reason is ReplayReason.QUOTA
    day = q.store.docs["dev/day/2026-10-10"]
    assert day["runs"] == {"anonymous": 4} and set(day["anon_slots"]) == {"00", "06", "12", "18"}
    assert set(day) <= {"_date", "runs", "anon_slots", "spent"}  # 利用者ごとのキー（IP 等）は作らない


def test_reservation_then_settlement_uses_the_actual_cost():
    q = svc()
    adm = run(q.admit())
    total = q.store.docs["dev/total"]
    assert list(total["reservations"].values())[0]["amount"] == RESERVATION_MICRO_JPY
    run(q.settle(adm, 3_000_000))
    total = q.store.docs["dev/total"]
    assert total["reservations"] == {} and total["spent"]["anonymous"] == 3_000_000
    assert q.store.docs["dev/day/2026-10-10"]["spent"]["anonymous"] == 3_000_000
    run(q.settle(adm, 3_000_000))  # 二重の精算は何もしない
    assert q.store.docs["dev/total"]["spent"]["anonymous"] == 3_000_000


def test_expired_reservations_are_swept_as_spent_at_the_reserved_amount():
    now = Now(datetime(2026, 10, 9, 15, 30, tzinfo=UTC))
    q = svc(now=now)
    run(q.admit())  # 精算されないまま（インスタンスが落ちた）
    now.advance(hours=6)
    run(q.admit())
    total = q.store.docs["dev/total"]
    assert total["spent"]["anonymous"] == RESERVATION_MICRO_JPY and len(total["reservations"]) == 1


def test_the_daily_yen_cap_counts_pending_reservations():
    policy = QUOTA_POLICY.model_copy(update={"judge": QUOTA_POLICY.judge.model_copy(update={"daily_cap_micro_jpy": RESERVATION_MICRO_JPY * 2})})
    q = svc(policy=policy)
    assert run(q.admit(JUDGE)).live and run(q.admit(JUDGE)).live
    adm = run(q.admit(JUDGE))
    assert adm.replay_reason is ReplayReason.BUDGET and adm.pool is Pool.JUDGE


def test_after_the_total_cap_anonymous_continues_at_one_run_a_day():
    pol = QUOTA_POLICY.model_copy(update={"anonymous": QUOTA_POLICY.anonymous.model_copy(update={"total_cap_micro_jpy": RESERVATION_MICRO_JPY})})
    now = Now(datetime(2026, 10, 9, 15, 30, tzinfo=UTC))
    q = svc(policy=pol, now=now)
    run(q.settle(run(q.admit()), RESERVATION_MICRO_JPY))  # 累計に到達
    now.advance(hours=6)
    assert run(q.admit()).replay_reason is ReplayReason.BUDGET  # 同じ日の2回目は不可
    now.advance(days=1)
    assert run(q.admit()).live  # 翌日に1回


# ---- 審査員枠 ---------------------------------------------------------------------------------------
def test_judge_pool_has_its_own_hourly_limit():
    q = svc()
    assert [run(q.admit(JUDGE)).pool for _ in range(3)] == [Pool.JUDGE] * 3
    adm = run(q.admit(JUDGE))
    assert adm.replay_reason is ReplayReason.QUOTA and adm.pool is Pool.JUDGE


def test_wrong_codes_fall_back_to_anonymous_and_lock_after_five_an_hour():
    now = Now(datetime(2026, 10, 9, 15, 30, tzinfo=UTC))
    q = svc(now=now)
    for _ in range(5):
        run(q.admit("guess"))
    assert q.store.docs["dev/day/2026-10-10"]["judge_failures"] == {"00": 5}
    assert run(q.admit(JUDGE)).pool is Pool.ANONYMOUS  # ロック中は正しいコードでも審査員枠に入らない
    now.advance(hours=1)
    assert run(q.admit(JUDGE)).pool is Pool.JUDGE  # 次の時間には解ける


def test_judge_code_comparison_is_constant_time_over_all_digests_and_handles_absence():
    assert judge_code_matches(JUDGE, [code_digest("x"), code_digest(JUDGE)])
    assert not judge_code_matches(JUDGE, [])
    assert run(svc(judge=()).admit(JUDGE)).pool is Pool.ANONYMOUS
    assert run(svc().admit("x" * 500)).pool is Pool.ANONYMOUS


def test_environments_do_not_share_counters():
    store = InMemoryState()
    run(svc(store=store).admit())
    assert run(svc(store=store, env=EnvName.STAGING).admit()).live
    assert {k.split("/")[0] for k in store.docs} == {"dev", "staging"}


def test_usage_from_trace_sums_estimated_costs():
    assert usage_from_trace([{"est_cost_micro_jpy": 5}, {"x": 1}, {"est_cost_micro_jpy": None}, {"est_cost_micro_jpy": 7}]) == 12


# ---- Firestore 実装（フェイクのクライアント。実接続はしない）-------------------------------------------
class _Snap:
    def __init__(self, data):
        self._d = data

    @property
    def exists(self):
        return self._d is not None

    def to_dict(self):
        return dict(self._d)


class _Ref:
    def __init__(self, db, path):
        self.db, self.path = db, path

    def get(self, transaction=None):
        return _Snap(self.db.data.get(self.path))


class _Coll:
    def __init__(self, db, name):
        self.db, self.name = db, name

    def document(self, doc_id):
        return _Ref(self.db, f"{self.name}/{doc_id}")


class _Tx:
    def __init__(self, db):
        self.db, self.writes = db, []

    def set(self, ref, value):
        self.writes.append((ref.path, value))

    def delete(self, ref):
        self.writes.append((ref.path, None))


class FakeFirestore:
    def __init__(self):
        self.data = {}

    def collection(self, name):
        return _Coll(self, name)

    def transaction(self):
        return _Tx(self)


def fake_transactional(fn):
    def run_tx(tx):
        out = fn(tx)
        for path, value in tx.writes:  # コミット
            if value is None:
                tx.db.data.pop(path, None)
            else:
                tx.db.data[path] = value
        return out

    return run_tx


def test_firestore_state_runs_the_same_quota_logic_through_transactions():
    db = FakeFirestore()
    store = FirestoreState(db, fake_transactional)
    assert isinstance(store, StatePort)
    q = svc(store=store)
    adm = run(q.admit())
    assert adm.live
    run(q.settle(adm, 1_000))
    assert db.data["claim_audit_state/dev__total"]["spent"] == {"anonymous": 1_000}
    assert run(store.get("dev/total"))["reservations"] == {}
