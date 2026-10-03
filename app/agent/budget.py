"""予算の計量（設計 §3 RUN_CAPS・§6-1）。契約の Budget（上限と使用量）に、時計とモデル呼び出しの「予約→精算」を足す。

モデル呼び出しは、呼ぶ前に最悪値（見積りの入力トークン＋出力の上限）を計上して枠を確保し（予約）、応答が返ったら実績で
精算する。応答が返らなかった呼び出し（切断・タイムアウト・例外）は最悪値のまま残す（§6-1: usage が戻らない呼び出しは最悪値で課金）。
並行に走る Reader の呼び出しが、同時に「あと1回ある」と判断して上限を超えることも、予約が防ぐ。

ここは判定に関わらない（数える・止めるだけ）。上限の値は config.RUN_CAPS が持つ。
"""
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.contracts import OBLIGATORY_KINDS, Budget, Kind, ModelPurpose, RawRequirement, RunCaps, Usage

Clock = Callable[[], float]  # 単調増加の秒（time.monotonic と同じ向き）


def estimate_tokens(text: str) -> int:
    """入力トークンの見積り（安全側）。日本語など非 ASCII は1字1トークン、ASCII は3字で1トークンとして切り上げる。"""
    ascii_n = sum(1 for ch in text if ord(ch) < 128)
    return (len(text) - ascii_n) + math.ceil(ascii_n / 3)


@dataclass(frozen=True)
class Reservation:
    purpose: ModelPurpose
    est_in: int
    est_out: int


class BudgetMeter:
    """Budget と時計。経過時間は呼び出しのたびに時計から更新する（Budget は値を持つだけで時計を持たない）。"""

    def __init__(self, caps: RunCaps, clock: Clock = time.monotonic) -> None:
        self.budget = Budget(caps=caps)
        self._clock = clock
        self._t0 = clock()

    @property
    def caps(self) -> RunCaps:
        return self.budget.caps

    def elapsed_ms(self) -> int:
        return max(0, int((self._clock() - self._t0) * 1000))

    def tick(self) -> int:
        ms = self.elapsed_ms()
        if ms > self.budget.elapsed_ms:
            self.budget.elapsed_ms = ms
        return self.budget.elapsed_ms

    def wall_expired(self) -> bool:
        return self.tick() >= self.caps.wall_clock_s * 1000

    def reserve_model(self, purpose: ModelPurpose, est_in: int, max_out: int) -> Reservation | None:
        """枠・トークン・壁時計に空きがあれば最悪値を計上して予約を返す。無ければ None（何も計上しない）。"""
        self.tick()
        if not self.budget.can_call_model(purpose, est_in, max_out):
            return None
        self.budget.charge_model_call(purpose, est_in, max_out)
        return Reservation(purpose, est_in, max_out)

    def settle_model(self, res: Reservation, usage: Usage | None) -> None:
        """実績で精算する。usage が無い（失敗）なら最悪値のまま。実績が見積りを超えたら超えた分も計上する。"""
        if usage is None:
            return
        self.budget.tokens_in = max(0, self.budget.tokens_in + usage.tokens_in - res.est_in)
        self.budget.tokens_out = max(0, self.budget.tokens_out + usage.tokens_out - res.est_out)


def requirement_cap(caps: RunCaps, kind: Kind) -> int:
    """申告された kind ごとの件数上限（必須・禁止は合わせて 64）。"""
    if kind in OBLIGATORY_KINDS:
        return caps.requirements_obligatory
    return {
        Kind.SPECULATIVE: caps.requirements_speculative,
        Kind.OPTIONAL: caps.requirements_optional,
        Kind.REQUEST: caps.requirements_request,
    }[kind]


def apply_requirement_caps(raws: Sequence[RawRequirement], caps: RunCaps) -> tuple[list[RawRequirement], int]:
    """件数上限（§3）を超えた分を、先着順で落とす。(残り, 落とした数)。

    上限は申告の kind で数える（検証の前に落とせば、棄却→再引用のモデル呼び出しを無駄にしない）。
    引用検証での降格（必須→任意など）の後に kind 別の件数が上限を超えることはありうる（合計は 64+8+8+8 まで）。
    """
    count: dict[object, int] = {}
    kept: list[RawRequirement] = []
    for r in raws:
        bucket: object = "obligatory" if r.kind in OBLIGATORY_KINDS else r.kind
        if count.get(bucket, 0) >= requirement_cap(caps, r.kind):
            continue
        count[bucket] = count.get(bucket, 0) + 1
        kept.append(r)
    return kept, len(raws) - len(kept)
