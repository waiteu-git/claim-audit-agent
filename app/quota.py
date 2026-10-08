"""ライブ実行の枠と費用の上限（設計 §6・§8）。予約→精算・審査員コード・匿名枠・キルスイッチの二重ラッチ・ADMIT 前段のゲート。

公開面（S2）の POST /api/run は、実行の前に QuotaService.admit を呼ぶ。答えは LIVE（予約つき）か REPLAY（理由つき）だけで、
ライブを許すかどうかはここ（コード）が決める。モデルの出力はこの判断に入らない。

  二重ラッチ   Settings.live_enabled（LIVE_ENABLED=1）かつ キルスイッチ（KILL_SWITCH・保存先の kill_live）が無い時だけライブ。
               どちらかが閉じていれば REPLAY。FATAL_CONFIG（Vertex の 4xx）が起きたら trip_kill で kill_live を自動で立てる。
  ADMIT ゲート インスタンス内で 1試行/秒（QUOTA_POLICY.admit_gate_per_s）。超えた要求は 429（AdmitRejected）。
  審査員コード URL の fragment `#j=…` を UI がヘッダ X-Judge に載せる（fragment はサーバーのログに残らない）。
               照合は sha256 の16進を hmac.compare_digest で比べる（コードそのものは保存しない）。失敗は1時間に5回でロック
               （ロック中は正しいコードでも審査員枠に入れず、匿名として扱う）。ログに残すのは sha256 の先頭8字だけ。
  匿名枠       全体で1日4回（JST の 0・6・12・18 時からの各6時間に1回）。IP などの利用者ごとのキーは作らない。
               累計の上限に達した後は1日1回に絞って続ける（QUOTA_POLICY.anonymous_runs_per_day_after_total）。
  費用         1実行ごとに RESERVATION_MICRO_JPY（最悪値）を予約し、終了時に実費（トレースの見積もり）で精算する。
               日次・累計の円上限は「使った額＋予約中の額＋今回の予約」で判定する。期限（開始＋130秒）切れの予約は、
               次の admit で予約額のまま使ったものとして掃除する（切断・落ちたインスタンスで枠が戻らない向き＝安全側）。
  fail-closed  保存先（StatePort）が失敗したら REPLAY（理由 STORE_UNAVAILABLE）。分からない時はライブを開けない。

保存先は StatePort（プロトコル）。テストはインメモリの InMemoryState、本番は app/state_firestore.py の FirestoreState。
文書は ENV ごとに分ける（`{env}/control`・`{env}/day/{YYYY-MM-DD}`・`{env}/total`）＝公開枠と開発の実行を混ぜない。
"""
import asyncio
import copy
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from app.config import QUOTA_POLICY, RESERVATION_MICRO_JPY, QuotaPolicy, Settings
from app.jsonlog import log_event

JST = timezone(timedelta(hours=9))
Docs = dict[str, dict[str, Any] | None]


@runtime_checkable
class StatePort(Protocol):
    """小さな文書ストア。transaction は keys の文書をまとめて読み、fn が返した新しい値を原子的に書く（None は削除）。"""

    async def transaction(self, keys: Sequence[str], fn: Callable[[Docs], Docs]) -> Docs: ...

    async def get(self, key: str) -> dict[str, Any] | None: ...


class InMemoryState:
    """StatePort のインメモリ実装（テスト・開発）。1つのロックで直列化する。fail を立てると全操作が例外（fail-closed の試験）。"""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self.fail = False

    async def transaction(self, keys: Sequence[str], fn: Callable[[Docs], Docs]) -> Docs:
        async with self._lock:
            if self.fail:
                raise ConnectionError("state store unavailable (test)")
            current: Docs = {k: copy.deepcopy(self.docs.get(k)) for k in keys}
            new = fn(current)
            for k, v in new.items():
                if k not in keys:
                    raise KeyError("transaction は読んだ文書にだけ書けます")
                if v is None:
                    self.docs.pop(k, None)
                else:
                    self.docs[k] = copy.deepcopy(v)
            return new

    async def get(self, key: str) -> dict[str, Any] | None:
        if self.fail:
            raise ConnectionError("state store unavailable (test)")
        return copy.deepcopy(self.docs.get(key))


class Pool(StrEnum):
    JUDGE = "judge"
    ANONYMOUS = "anonymous"


class ReplayReason(StrEnum):
    LIVE_DISABLED = "LIVE_DISABLED"  # LIVE_ENABLED が閉じている
    KILLED = "KILLED"  # キルスイッチ（環境変数・保存先の kill_live）
    QUOTA = "QUOTA"  # 回数の枠を使い切った
    BUDGET = "BUDGET"  # 円の上限（日次・累計）
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"  # 保存先に届かない（fail-closed）
    NOT_LIVE_PRESET = "NOT_LIVE_PRESET"  # 保存済みの実行しか持たないプリセット
    LIVE_TIMEOUT = "LIVE_TIMEOUT"  # ライブ実行が時間内に終わらず、実行の途中で保存済みの実行へ切り替えた（ADMIT の判断ではない。web が付ける）


class AdmitRejected(Exception):
    """ADMIT 前段のゲート（1試行/秒）で断った。公開面は 429 を返す。"""


class JudgeRequired(Exception):
    """審査員コード専用の入口で、コードが無い・合わない（ロック中を含む）。公開面は 403 を返す。枠は使わない。"""


@dataclass(frozen=True)
class Admission:
    live: bool
    pool: Pool | None = None
    reservation_id: str | None = None
    reserved_micro_jpy: int = 0
    replay_reason: ReplayReason | None = None


@dataclass
class _Gate:
    per_s: int
    clock: Callable[[], float]
    _stamps: list[float] = field(default_factory=list)

    def take(self) -> bool:
        now = self.clock()
        self._stamps = [t for t in self._stamps if now - t < 1.0]
        if len(self._stamps) >= self.per_s:
            return False
        self._stamps.append(now)
        return True


def code_digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def judge_code_matches(code: str, digests: Sequence[str]) -> bool:
    """審査員コードの照合（sha256 の16進を定数時間で比べる。全件を比べて、どれに当たったかで時間を変えない）。"""
    got = code_digest(code)
    ok = False
    for d in digests:
        ok |= hmac.compare_digest(got, d)
    return ok


class QuotaService:
    def __init__(
        self,
        settings: Settings,
        store: StatePort,
        *,
        policy: QuotaPolicy = QUOTA_POLICY,
        reservation_micro_jpy: int = RESERVATION_MICRO_JPY,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        kill_cache_s: float = 5.0,
    ) -> None:
        self.settings = settings
        self.store = store
        self.policy = policy
        self.reservation = reservation_micro_jpy
        self.now = now
        self._mono = monotonic
        self._gate = _Gate(policy.admit_gate_per_s, monotonic)
        self._kill_cache: tuple[float, bool] | None = None
        self._kill_cache_s = kill_cache_s
        env = settings.env.value
        self.k_control = f"{env}/control"
        self.k_total = f"{env}/total"

    # ---- 鍵 ---------------------------------------------------------------------------------------
    def _jst(self) -> datetime:
        return self.now().astimezone(JST)

    def k_day(self) -> str:
        return f"{self.settings.env.value}/day/{self._jst().date().isoformat()}"

    # ---- キルスイッチ（二重ラッチの片方。保存先の kill_live は5秒キャッシュ）---------------------------
    async def killed(self) -> bool:
        if self.settings.kill_switch:
            return True
        now = self._mono()
        if self._kill_cache is not None and now - self._kill_cache[0] < self._kill_cache_s:
            return self._kill_cache[1]
        doc = await self.store.get(self.k_control)
        k = bool((doc or {}).get("kill_live", False))
        self._kill_cache = (now, k)
        return k

    async def trip_kill(self) -> None:
        """FATAL_CONFIG（Vertex の設定の誤り）で kill_live を立てる。解除は人が保存先を直す。"""
        await self.store.transaction([self.k_control], lambda d: {self.k_control: {**(d[self.k_control] or {}), "kill_live": True}})
        self._kill_cache = (self._mono(), True)
        log_event("quota.kill_live_tripped", severity="WARNING")

    async def mode(self) -> str:
        """UI のモード表示: LIVE（ライブの余地あり）／REPLAY（保存済みの再生だけ）／STOPPED（キルスイッチ）。枠は消費しない。"""
        try:
            if await self.killed():
                return "STOPPED"
        except Exception:  # noqa: BLE001  分からない時は開けない
            return "REPLAY"
        return "LIVE" if self.settings.live_enabled else "REPLAY"

    # ---- ADMIT --------------------------------------------------------------------------------------
    async def admit(self, judge_header: str | None = None, *, judge_only: bool = False) -> Admission:
        """judge_only=True（審査員コード専用の入口）では、コードが無い・合わない時に JudgeRequired を投げ、匿名の枠は使わない。
        コードが合えば審査員の枠を予約する。失敗の数え方（1時間に5回でロック）は通常の経路と同じ。"""
        if not self._gate.take():
            raise AdmitRejected()
        if judge_only and not judge_header:
            raise JudgeRequired()
        if not self.settings.live_enabled:
            return Admission(False, replay_reason=ReplayReason.LIVE_DISABLED)
        try:
            if await self.killed():
                return Admission(False, replay_reason=ReplayReason.KILLED)
            pool = Pool.ANONYMOUS
            if judge_header:
                pool = Pool.JUDGE if await self._judge_ok(judge_header) else Pool.ANONYMOUS
            if judge_only and pool is not Pool.JUDGE:
                raise JudgeRequired()
            return await self._reserve(pool)
        except JudgeRequired:
            raise
        except Exception as e:  # noqa: BLE001  fail-closed
            log_event("quota.store_unavailable", severity="ERROR", error_type=type(e).__name__)
            return Admission(False, replay_reason=ReplayReason.STORE_UNAVAILABLE)

    async def _judge_ok(self, code: str) -> bool:
        if len(code) > 128 or not self.settings.judge_code_sha256:
            ok = False
        else:
            ok = judge_code_matches(code, self.settings.judge_code_sha256)
        hour = f"{self._jst().hour:02d}"
        k_day = self.k_day()
        limit = self.policy.judge_lock_failures_per_hour
        result: dict[str, bool] = {}

        def fn(d: Docs) -> Docs:
            day = d[k_day] or {}
            fails = dict(day.get("judge_failures", {}))
            locked = fails.get(hour, 0) >= limit
            if not ok and not locked:
                fails[hour] = fails.get(hour, 0) + 1
            result["accepted"] = ok and not locked
            result["locked"] = locked or fails.get(hour, 0) >= limit
            return {k_day: {**day, "judge_failures": fails}}

        await self.store.transaction([k_day], fn)
        log_event(
            "quota.judge_code", accepted=result["accepted"], locked=result["locked"], code_sha256_8=code_digest(code)[:8]
        )  # fmt: skip
        return result["accepted"]

    def _sweep(self, total: dict[str, Any], day: dict[str, Any], now_ts: float) -> None:
        """期限切れの予約を、予約額を使ったものとして精算する（枠が戻らない向き）。"""
        res = dict(total.get("reservations", {}))
        for rid, r in list(res.items()):
            if r["expires"] <= now_ts:
                del res[rid]
                _add_spent(total, r["pool"], r["amount"])
                if r.get("day") == day.get("_date"):
                    _add_spent(day, r["pool"], r["amount"])
        total["reservations"] = res

    async def _reserve(self, pool: Pool) -> Admission:
        k_day, k_total = self.k_day(), self.k_total
        jst = self._jst()
        now_ts = self.now().timestamp()
        pol = self.policy.judge if pool is Pool.JUDGE else self.policy.anonymous
        rid = secrets.token_urlsafe(12)
        amount = self.reservation
        out: dict[str, Any] = {}

        def fn(d: Docs) -> Docs:
            day = dict(d[k_day] or {})
            day["_date"] = jst.date().isoformat()
            total = dict(d[k_total] or {})
            self._sweep(total, day, now_ts)
            res = total.get("reservations", {})
            pending_day = sum(r["amount"] for r in res.values() if r["pool"] == pool.value and r.get("day") == day["_date"])
            pending_total = sum(r["amount"] for r in res.values() if r["pool"] == pool.value)
            spent_day = day.get("spent", {}).get(pool.value, 0)
            spent_total = total.get("spent", {}).get(pool.value, 0)
            runs = dict(day.get("runs", {}))
            n_day = runs.get(pool.value, 0)
            over_total = spent_total + pending_total + amount > pol.total_cap_micro_jpy
            reason: ReplayReason | None = None
            if pool is Pool.ANONYMOUS:
                slot_key = _slot(jst.hour, self.policy.anonymous_slot_hours_jst)
                slots = dict(day.get("anon_slots", {}))
                if over_total:
                    if n_day >= self.policy.anonymous_runs_per_day_after_total:
                        reason = ReplayReason.BUDGET
                elif slots.get(slot_key, 0) >= 1 or n_day >= pol.runs_per_day:
                    reason = ReplayReason.QUOTA
            else:
                hours = dict(day.get("judge_hours", {}))
                if over_total:
                    reason = ReplayReason.BUDGET
                elif n_day >= pol.runs_per_day or (pol.runs_per_hour is not None and hours.get(f"{jst.hour:02d}", 0) >= pol.runs_per_hour):
                    reason = ReplayReason.QUOTA
            if reason is None and spent_day + pending_day + amount > pol.daily_cap_micro_jpy:
                reason = ReplayReason.BUDGET
            if reason is not None:
                out["reason"] = reason
                return {k_day: day, k_total: total}  # 掃除の結果だけ書く
            runs[pool.value] = n_day + 1
            day["runs"] = runs
            if pool is Pool.ANONYMOUS:
                slots[slot_key] = slots.get(slot_key, 0) + 1
                day["anon_slots"] = slots
            else:
                hours[f"{jst.hour:02d}"] = hours.get(f"{jst.hour:02d}", 0) + 1
                day["judge_hours"] = hours
            res = dict(res)
            res[rid] = {"pool": pool.value, "amount": amount, "expires": now_ts + self.policy.reservation_ttl_s, "day": day["_date"]}
            total["reservations"] = res
            return {k_day: day, k_total: total}

        await self.store.transaction([k_day, k_total], fn)
        if "reason" in out:
            return Admission(False, pool=pool, replay_reason=out["reason"])
        log_event("quota.reserved", pool=pool.value, amount_micro_jpy=amount)
        return Admission(True, pool=pool, reservation_id=rid, reserved_micro_jpy=amount)

    async def settle(self, admission: Admission, actual_micro_jpy: int) -> None:
        """予約を実費で精算する。予約が既に掃除されていれば何もしない（掃除で予約額を計上済み）。"""
        if not admission.live or admission.reservation_id is None or admission.pool is None:
            return
        rid, pool = admission.reservation_id, admission.pool
        k_total = self.k_total
        found: dict[str, Any] = {}

        def fn_total(d: Docs) -> Docs:
            total = dict(d[k_total] or {})
            res = dict(total.get("reservations", {}))
            r = res.pop(rid, None)
            if r is None:
                return {k_total: total}
            found.update(r)
            total["reservations"] = res
            _add_spent(total, pool.value, max(0, actual_micro_jpy))
            return {k_total: total}

        await self.store.transaction([k_total], fn_total)
        if not found:
            return
        k_day = f"{self.settings.env.value}/day/{found['day']}"

        def fn_day(d: Docs) -> Docs:
            day = dict(d[k_day] or {})
            _add_spent(day, pool.value, max(0, actual_micro_jpy))
            return {k_day: day}

        await self.store.transaction([k_day], fn_day)
        log_event("quota.settled", pool=pool.value, actual_micro_jpy=actual_micro_jpy)


def _add_spent(doc: dict[str, Any], pool: str, amount: int) -> None:
    spent = dict(doc.get("spent", {}))
    spent[pool] = spent.get(pool, 0) + amount
    doc["spent"] = spent


def _slot(hour: int, slot_hours: Sequence[int]) -> str:
    start = max((h for h in slot_hours if h <= hour), default=slot_hours[0])
    return f"{start:02d}"


def usage_from_trace(events: Sequence[Mapping[str, Any]] | Sequence[Any]) -> int:
    """トレースの model_call の見積もり費用の合計（micro 円）。精算の実費に使う。"""
    total = 0
    for e in events:
        v = e.get("est_cost_micro_jpy") if isinstance(e, Mapping) else getattr(e, "est_cost_micro_jpy", None)
        total += int(v or 0)
    return total
