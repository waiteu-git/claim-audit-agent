"""Governor: Planner（と router）の関数呼び出しを、実行ごとの上限と規則で許可／拒否するコード（設計 §2・§3・§4）。

モデルは提案するだけで、実行するかはここが決める。拒否は例外でなく Admission(deny) で返し、必ず policy_id と理由コードを
トレースに残す（P-xxx の意味は下の表）。上限到達は理由つきの DEGRADED／ABORTED にする（例外にしない）。

  P-KILL-01          キルスイッチ（settings.kill_switch）。実行を ABORTED(KILL) にする
  P-PHASE-02         この状態では呼べない呼び出し: 未知の関数名・今ターンの許可リスト外・引数の型違い・存在しない req_id・
                     推測や引用なしの要件への run_check・要件クラスと合わない checker・finish の時期尚早は P-MINTURN-01
  P-LINK-01          存在しない link_id・ログインのリンク
  P-SCOPE-01         スコープ外のリンク・提出URLが無い
  P-DUP-01           同じ呼び出しの繰り返し（reason の言い換えで回避させないため、reason は照合に含めない）。拒否された呼び出しを
                     状態（観測・印・ツール呼び出し数）が変わらないまま繰り返すと REPEATED_DENIAL（理由を再計算せず即座に拒否）
  P-BUDGET-CALLS-01  ツール呼び出し・取得・第三者 origin・要件ごとの3回・モデル呼び出しの枠
  P-BUDGET-TOKENS-01 トークンの枠
  P-UNVERIF-01       mark_unverifiable の前提（コードが付ける理由コードは Planner に付けさせない。NEEDS_AUTH / NEEDS_JS は前提の観測が要る。
                     検査できる要件には、その検査を一度走らせた後だけ付けられる＝検査を省いて不適合を洗えない）。
                     許可リスト（allowed_tools）には、Planner の付けられる理由が実際にある要件が残る時だけ載せる
                     （10/7 のライブ実行で、通らない mark_unverifiable を出し続けて拒否の連続で DEGRADED になったため）。
  P-MINTURN-01       finish が早すぎる（検査できる要件に、まだ1回も検査していないものが残っている）。予算が尽きた時と最終ターンは通す
  P-INJ-01           注入疑い区間に重なる引用（Reader の引用検証が出す。ここでは発行しない）

停止の優先順: ABORTED（KILL > WALL_CLOCK）> DEGRADED（BUDGET > DENIAL_STREAK）。最初に決まった理由を残す。
判定（Verdict）はここでは作らない（adjudicate.py だけ）。
"""
import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.agent.budget import BudgetMeter, Reservation
from app.agent.state import RunState
from app.agent.trace import TraceLog, digest
from app.config import PRICE_TABLE
from app.contracts import (
    CHECK_CLASS_CHECKER,
    AbortReason,
    DenialCode,
    Actor,
    Decision,
    DegradedReason,
    FetchKind,
    FunctionCall,
    Kind,
    LinkRole,
    ModelPurpose,
    ModelResponse,
    ObsCode,
    Phase,
    PolicyId,
    ReqState,
    RunStatus,
    ToolCall,
    ToolName,
    TraceType,
    UnverifiableReason,
    Usage,
    parse_tool_call,
)
from app.errors import AppError

# Phase の遷移表（§3）。DEGRADED / ABORTED は状態（status）で持ち、フェーズは REPORT まで進める（部分結果を必ず返す）
_NEXT: dict[Phase, frozenset[Phase]] = {
    Phase.ADMIT: frozenset({Phase.ACQUIRE}),
    Phase.ACQUIRE: frozenset({Phase.READ}),
    Phase.READ: frozenset({Phase.AUTORUN, Phase.INSPECT}),
    Phase.AUTORUN: frozenset({Phase.INSPECT}),
    Phase.INSPECT: frozenset({Phase.ADJUDICATE}),
    Phase.ADJUDICATE: frozenset({Phase.REPORT}),
    Phase.REPORT: frozenset({Phase.PERSIST, Phase.DONE}),
    Phase.PERSIST: frozenset({Phase.DONE}),
    Phase.DONE: frozenset(),
    Phase.DEGRADED: frozenset(),
    Phase.ABORTED: frozenset(),
    Phase.REPLAY: frozenset(),
}

# Planner が mark_unverifiable で付けてよい理由コード。残り（BUDGET・NO_EVIDENCE・TRUNCATED・TRANSIENT・FETCH_BLOCKED・
# UNSUPPORTED_TYPE）は、コードが観測と予算から決める。Planner が「予算切れ」「証拠なし」と言って検査を省けないようにする。
PLANNER_MARK_CODES = frozenset(
    {
        UnverifiableReason.NEEDS_AUTH,
        UnverifiableReason.NEEDS_JS,
        UnverifiableReason.HUMAN_ONLY,
        UnverifiableReason.FUTURE,
        UnverifiableReason.OUT_OF_SCOPE,
        UnverifiableReason.NOT_PUBLIC,
    }
)


@dataclass(frozen=True)
class Admission:
    """1回の関数呼び出しへの Governor の答え。allowed なら call が検証済みの ToolCall。"""

    call: ToolCall | None = None
    policy: PolicyId | None = None
    reason: str | None = None
    premise_obs_id: str | None = None  # mark_unverifiable の前提の観測（NEEDS_AUTH / NEEDS_JS）

    @property
    def allowed(self) -> bool:
        return self.call is not None


def _origin_alias(host: str) -> str:
    """第三者 origin の別名（ホスト名そのものはトレースへ出さない）。"""
    return "h" + hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]


def _call_key(call: ToolCall) -> str:
    """重複検知の鍵。reason は自由文なので含めない（言い換えで同じ呼び出しを繰り返させない）。"""
    args = call.args.model_dump(mode="json")
    args.pop("reason", None)
    return f"{call.name.value}:{digest(args)}"


@dataclass
class Governor:
    state: RunState
    meter: BudgetMeter
    trace: TraceLog
    kill_switch: "bool | Callable[[], bool]" = False  # bool、または呼ぶと bool を返す関数（実行中に切り替わるキルスイッチ）
    phase: Phase = Phase.ADMIT
    status: RunStatus = RunStatus.DONE
    degraded_reason: DegradedReason | None = None
    aborted_reason: AbortReason | None = None
    denied: int = 0
    denial_streak: int = 0
    turn: int = 0
    max_turns: int = 1
    turn_allowed: tuple[ToolName, ...] = ()
    last_denial: DenialCode | None = None  # 直前の拒否（StateView に載せる）。許可で消える
    last_denied_tool: ToolName | None = None
    _seen: dict[str, int] = field(default_factory=dict)  # 呼び出しの鍵 → 許可した時点の観測の数
    _denied: dict[str, tuple[int, int, int]] = field(default_factory=dict)  # 拒否した呼び出しの鍵 → 拒否した時点の状態

    # ---- フェーズ ------------------------------------------------------------------------------
    def enter(self, phase: Phase) -> None:
        if phase not in _NEXT.get(self.phase, frozenset()):
            raise ValueError(f"フェーズ遷移が不正です: {self.phase.value} → {phase.value}")
        self.phase = phase
        self.trace.emit(phase, Actor.GOVERNOR, TraceType.PHASE_ENTER, name=phase.value)

    # ---- 停止 ----------------------------------------------------------------------------------
    def _killed(self) -> bool:
        k = self.kill_switch
        return bool(k() if callable(k) else k)

    def abort(self, reason: AbortReason) -> None:
        if self.status is RunStatus.ABORTED:
            return
        self.status, self.aborted_reason = RunStatus.ABORTED, reason
        self.trace.emit(self.phase, Actor.GOVERNOR, TraceType.ABORT, name=self.phase.value, reason_code=reason.value)

    def degrade(self, reason: DegradedReason) -> None:
        """部分結果を返す終端。最初の理由を残し、ABORTED を上書きしない。"""
        if self.status is not RunStatus.DONE:
            return
        self.status, self.degraded_reason = RunStatus.DEGRADED, reason
        self.trace.emit(
            self.phase, Actor.GOVERNOR, TraceType.PHASE_ENTER, name=Phase.DEGRADED.value, reason_code=reason.value
        )

    @property
    def stopped(self) -> bool:
        return self.status is not RunStatus.DONE

    def check_stop(self) -> bool:
        """停止条件を見て、決まれば status を変える。続けてよければ False。"""
        if self.status is RunStatus.ABORTED:
            return True
        if self._killed():
            self._deny_event(PolicyId.KILL, "KILLED")
            self.abort(AbortReason.KILL)
            return True
        if self.meter.wall_expired():
            self.abort(AbortReason.WALL_CLOCK)
            return True
        if self.status is RunStatus.DEGRADED:
            return True
        if self.meter.budget.exhausted() is not None:
            self.degrade(DegradedReason.BUDGET)
            return True
        if self.denial_streak >= self.meter.caps.consecutive_denials_stop:
            self.degrade(DegradedReason.DENIAL_STREAK)
            return True
        return False

    def snapshot(self) -> None:
        self.trace.emit(self.phase, Actor.GOVERNOR, TraceType.BUDGET_SNAPSHOT, budget=self.meter.budget.snapshot())

    # ---- 拒否の記録 ----------------------------------------------------------------------------
    def _deny_event(self, policy: PolicyId, reason: str, **fields: object) -> None:
        self.trace.emit(
            self.phase,
            Actor.GOVERNOR,
            TraceType.POLICY_DECISION,
            policy_id=policy,
            decision=Decision.DENY,
            reason_code=reason,
            **fields,
        )

    def _deny(self, policy: PolicyId, reason: str, *, name: str | None = None, req_id: str | None = None) -> Admission:
        self.denied += 1
        self.denial_streak += 1
        self._deny_event(policy, reason, name=name, req_id=req_id)
        self.last_denial = DenialCode(reason) if reason in DenialCode.__members__ else None
        self.last_denied_tool = ToolName(name) if name in {t.value for t in ToolName} else None
        return Admission(policy=policy, reason=reason)

    def _state_mark(self) -> tuple[int, int, int]:
        """拒否の繰り返しを見分けるための状態の指紋（観測の数・印の数・ツール呼び出しの数）。"""
        return (len(self.state.observations), len(self.state.marks), self.meter.budget.tool_calls)

    def deny_no_call(self) -> None:
        """Planner が関数を呼ばずに応答した。何も実行されないが、拒否の連続として数える（自由文で時間を使わせない）。"""
        self._deny(PolicyId.PHASE, "NO_CALL", name=ModelPurpose.PLANNER.value)

    # ---- モデル呼び出し ------------------------------------------------------------------------
    def reserve_model(self, purpose: ModelPurpose, est_in: int, max_out: int) -> Reservation | None:
        """モデル呼び出しの枠を予約する。キルスイッチ・枠切れ・トークン切れ・時間切れなら None（理由はトレースと status に残す）。"""
        if self._killed():
            self._deny_event(PolicyId.KILL, "KILLED", name=purpose.value)
            self.abort(AbortReason.KILL)
            return None
        if self.meter.wall_expired():
            self.abort(AbortReason.WALL_CLOCK)
            return None
        res = self.meter.reserve_model(purpose, est_in, max_out)
        if res is None:
            b = self.meter.budget
            if b.tokens_in + est_in > b.caps.tokens_in or b.tokens_out + max_out > b.caps.tokens_out:
                self._deny_event(PolicyId.BUDGET_TOKENS, "TOKENS", name=purpose.value)
            else:
                self._deny_event(PolicyId.BUDGET_CALLS, "MODEL_CALLS", name=purpose.value)
            self.denied += 1
        return res

    def settle_model(
        self,
        res: Reservation,
        resp: ModelResponse | None,
        *,
        model_id: str,
        error_code: str | None = None,
        req_id: str | None = None,
    ) -> None:
        """応答（無ければ失敗）で精算し、model_call イベントを残す。"""
        usage: Usage | None = resp.usage if resp is not None else None
        self.meter.settle_model(res, usage)
        t_in = usage.tokens_in if usage else res.est_in
        t_out = usage.tokens_out if usage else res.est_out
        self.trace.emit(
            self.phase,
            Actor.READER if res.purpose is ModelPurpose.READER else Actor.PLANNER,
            TraceType.MODEL_CALL,
            name=res.purpose.value,
            req_id=req_id,
            model=model_id,
            purpose=res.purpose,
            finish_reason=(resp.finish_reason if resp is not None else None),
            reason_code=error_code,
            tokens_in=t_in,
            tokens_out=t_out,
            est_cost_micro_jpy=PRICE_TABLE.cost_micro_jpy(model_id, t_in, t_out),
            latency_ms=resp.latency_ms if resp is not None else None,
        )

    # ---- 許可リスト ----------------------------------------------------------------------------
    def pending_checks(self) -> list[str]:
        """検査できる要件のうち、まだ1回も検査していない OPEN のもの（router の作業リスト・finish の関門）。"""
        out = []
        for r in self.state.requirements:
            if self.state.is_checkable(r) and self.state.req_state(r) is ReqState.OPEN and self.state.calls_used(r.req_id) == 0:
                out.append(r.req_id)
        return out

    def _openable(self) -> list:
        return [r for r in self.state.requirements if self.state.req_state(r) is ReqState.OPEN]

    def _probe_targets_left(self) -> bool:
        st, b = self.state, self.meter.budget
        if not b.can_fetch(kind=FetchKind.HTTP_PROBE):
            return False
        if st.preset.submission_url and "SUBMISSION_URL" not in st.probed_targets:
            return True
        return any(r.entry.in_scope and r.entry.role is not LinkRole.LOGIN and gid not in st.probed_targets for gid, r in st.links.items())

    def _links_left(self) -> bool:
        st, b = self.state, self.meter.budget
        if not b.can_fetch(kind=FetchKind.FETCH_LINK):
            return False
        return any(
            r.entry.in_scope and r.entry.role is not LinkRole.LOGIN and gid not in st.fetched_links
            for gid, r in st.links.items()
        )

    def allowed_tools(self) -> tuple[ToolName, ...]:
        """このターンに呼べる関数名。モデルへ渡す宣言と照合の両方がこれを使う（宣言に無い関数は呼べない）。"""
        b = self.meter.budget
        if not b.can_call_tool():
            return (ToolName.FINISH,)
        tools: list[ToolName] = []
        if self._links_left():
            tools.append(ToolName.FETCH_LINK)
        if self._probe_targets_left():
            tools.append(ToolName.HTTP_PROBE)
        st = self.state
        if any(
            st.is_checkable(r) and st.req_state(r) is ReqState.OPEN and st.calls_used(r.req_id) < self.meter.caps.tool_calls_per_requirement
            for r in st.requirements
        ):
            tools.append(ToolName.RUN_CHECK)
        if self.markable_reqs():
            tools.append(ToolName.MARK_UNVERIFIABLE)
        tools.append(ToolName.FINISH)
        return tuple(tools)

    def markable_reqs(self) -> list[str]:
        """Planner が mark_unverifiable を通せる要件（PLANNER_MARK_CODES のどれかで前提が揃うもの）。

        _check_mark の拒否条件のうち、理由コードに依らないもの（推測・印あり・決着済み・検査前・要件ごとの枠）を先に除く。
        残った要件には HUMAN_ONLY などの前提の要らない理由が必ず通るので、許可リストに載せてよい。"""
        st, cap = self.state, self.meter.caps.tool_calls_per_requirement
        out = []
        for r in self._openable():
            if r.kind is Kind.SPECULATIVE or r.req_id in st.marks or st.calls_used(r.req_id) >= cap:
                continue
            if st.is_checkable(r) and not st.check_observations(r.req_id):
                continue  # CHECK_FIRST: 検査できる要件は検査を一度走らせてから
            out.append(r.req_id)
        return out

    def begin_turn(self, turn: int, max_turns: int, allowed: Sequence[ToolName]) -> None:
        self.turn, self.max_turns, self.turn_allowed = turn, max_turns, tuple(allowed)

    # ---- 関数呼び出しの許可 --------------------------------------------------------------------
    def admit(self, raw: "FunctionCall | ToolCall") -> Admission:
        """関数呼び出し1つを許可／拒否する。許可なら予算を計上し、重複検知に記録する。"""
        if self._killed():
            self._deny_event(PolicyId.KILL, "KILLED")
            self.abort(AbortReason.KILL)
            return Admission(policy=PolicyId.KILL, reason="KILLED")
        if self.stopped:
            return Admission(policy=PolicyId.PHASE, reason="STOPPED")

        if isinstance(raw, ToolCall):
            call = raw
            name = raw.name.value
        else:
            name = raw.name
            if name not in {t.value for t in ToolName}:
                return self._deny(PolicyId.PHASE, "UNKNOWN_TOOL")  # 名前はモデルの出力なので、トレースへ載せない
            if ToolName(name) not in self.turn_allowed:
                return self._deny(PolicyId.PHASE, "TOOL_NOT_ALLOWED", name=name)
            try:
                call = parse_tool_call(name, raw.args)
            except AppError:
                return self._deny(PolicyId.PHASE, "BAD_ARGS", name=name)
        if call.name not in self.turn_allowed:
            return self._deny(PolicyId.PHASE, "TOOL_NOT_ALLOWED", name=name)

        key = _call_key(call)
        # finish の拒否（時期尚早）はターンと予算で変わるので、繰り返しの即時拒否から外す
        if call.name is not ToolName.FINISH and self._denied.get(key) == self._state_mark():
            # 拒否された呼び出しを、何も変わらないまま繰り返した。理由は前回と同じなので再計算せず P-DUP-01 で止める
            # （拒否の連続に数えるので、繰り返す Planner は consecutive_denials_stop で DEGRADED になる）
            return self._deny(PolicyId.DUP, "REPEATED_DENIAL", name=name, req_id=getattr(call.args, "req_id", None))
        adm = self._admit_parsed(call, name, key)
        if not adm.allowed:
            self._denied[key] = self._state_mark()
        return adm

    def _admit_parsed(self, call: ToolCall, name: str, key: str) -> Admission:
        """検証済みの呼び出しの許可（予算・引数・重複）。"""
        b = self.meter.budget
        if not b.can_call_tool():
            return self._deny(PolicyId.BUDGET_CALLS, "TOOL_CAP", name=name)

        verdict = self._check_args(call)
        if verdict is not None:
            return verdict

        n_obs = len(self.state.observations)
        last = self._seen.get(key)
        # 同じ呼び出しの繰り返しは拒否する。ただし run_check だけは、前回の許可の後に別の観測が増えていれば（前回の1件は自分の結果）
        # 新しい証拠のもとでのやり直しとして許す（probe の前に auth_wall を呼んで不確定だった後、probe してから呼び直す等）。
        # 繰り返しの総数は要件ごとの3回と全体の16回が抑える。
        if last is not None and not (call.name is ToolName.RUN_CHECK and n_obs > last + 1):
            return self._deny(PolicyId.DUP, "DUPLICATE_CALL", name=name, req_id=getattr(call.args, "req_id", None))
        # --- 許可 ---
        self._seen[key] = n_obs
        b.charge_tool_call()
        req_id = getattr(call.args, "req_id", None)
        if req_id is not None and call.name in (ToolName.RUN_CHECK, ToolName.MARK_UNVERIFIABLE):
            self.state.req_calls[req_id] = self.state.calls_used(req_id) + 1
        self.denial_streak = 0
        self.last_denial = self.last_denied_tool = None
        self.trace.emit(
            self.phase, Actor.PLANNER, TraceType.TOOL_REQUEST, name=name, req_id=req_id,
            args_digest=digest(call.args.model_dump(mode="json")),
        )  # fmt: skip
        self.trace.emit(
            self.phase, Actor.GOVERNOR, TraceType.POLICY_DECISION, name=name, req_id=req_id,
            policy_id=PolicyId.PHASE, decision=Decision.ALLOW, reason_code="OK",
        )  # fmt: skip
        return Admission(call=call, premise_obs_id=self._premise(call))

    # ---- 個別の検査 ----------------------------------------------------------------------------
    def _check_args(self, call: ToolCall) -> Admission | None:
        st, b = self.state, self.meter.budget
        name = call.name.value
        a = call.args
        if call.name is ToolName.FINISH:
            if self.turn < self.max_turns and b.exhausted() is None and self.pending_checks():
                return self._deny(PolicyId.MINTURN, "OPEN_REQUIREMENTS", name=name)
            return None
        if call.name is ToolName.FETCH_LINK:
            ref = st.links.get(a.link_id)  # type: ignore[union-attr]
            if ref is None:
                return self._deny(PolicyId.LINK, "UNKNOWN_LINK", name=name)
            if not ref.entry.in_scope:
                return self._deny(PolicyId.SCOPE, "OUT_OF_SCOPE", name=name)
            if ref.entry.role is LinkRole.LOGIN:
                return self._deny(PolicyId.LINK, "LOGIN_LINK", name=name)
            return self._fetch_budget(name, FetchKind.FETCH_LINK, ref.entry.href)
        if call.name is ToolName.HTTP_PROBE:
            target = a.target  # type: ignore[union-attr]
            if target == "SUBMISSION_URL":
                if not st.preset.submission_url:
                    return self._deny(PolicyId.SCOPE, "NO_SUBMISSION_URL", name=name)
                return self._fetch_budget(name, FetchKind.HTTP_PROBE, st.preset.submission_url)
            ref = st.links.get(target)
            if ref is None:
                return self._deny(PolicyId.LINK, "UNKNOWN_LINK", name=name)
            if not ref.entry.in_scope:
                return self._deny(PolicyId.SCOPE, "OUT_OF_SCOPE", name=name)
            return self._fetch_budget(name, FetchKind.HTTP_PROBE, ref.entry.href)
        req = st.req(a.req_id)  # type: ignore[union-attr]
        if req is None:
            return self._deny(PolicyId.PHASE, "UNKNOWN_REQ", name=name)
        if call.name is ToolName.RUN_CHECK:
            if not st.is_checkable(req):
                return self._deny(PolicyId.PHASE, "NOT_CHECKABLE", name=name, req_id=req.req_id)
            if CHECK_CLASS_CHECKER[req.check_class] is not a.checker:  # type: ignore[union-attr]
                return self._deny(PolicyId.PHASE, "CLASS_MISMATCH", name=name, req_id=req.req_id)
            if st.calls_used(req.req_id) >= self.meter.caps.tool_calls_per_requirement:
                return self._deny(PolicyId.BUDGET_CALLS, "REQ_CAP", name=name, req_id=req.req_id)
            return None
        return self._check_mark(call, req)

    def _fetch_budget(self, name: str, kind: FetchKind, href: str) -> Admission | None:
        b = self.meter.budget
        origin = self._third_party_origin(href)
        if not b.can_fetch(origin, kind):
            reason = "ORIGIN_CAP" if origin is not None and b.can_fetch(None, kind) else "FETCH_CAP"
            return self._deny(PolicyId.BUDGET_CALLS, reason, name=name)
        return None

    def third_party_origin(self, href: str) -> str | None:
        return self._third_party_origin(href)

    def _third_party_origin(self, href: str) -> str | None:
        """プリセットの要項・提出URL以外のホストなら、その別名（予算の第三者 origin に数える）。"""
        host = (urlsplit(href).hostname or "").lower()
        p = self.state.preset
        own = {(urlsplit(u).hostname or "").lower() for u in (*p.spec_seed_urls, *([p.submission_url] if p.submission_url else []))}
        return None if host in own else _origin_alias(host)

    def _check_mark(self, call: ToolCall, req) -> Admission | None:  # noqa: ANN001
        st = self.state
        name = call.name.value
        code = call.args.reason_code  # type: ignore[union-attr]
        if req.kind is Kind.SPECULATIVE:
            return self._deny(PolicyId.UNVERIF, "SPECULATIVE", name=name, req_id=req.req_id)
        if code not in PLANNER_MARK_CODES:
            return self._deny(PolicyId.UNVERIF, "CODE_ONLY", name=name, req_id=req.req_id)
        if req.req_id in st.marks or st.req_state(req) is ReqState.DONE:
            return self._deny(PolicyId.UNVERIF, "ALREADY_DECIDED", name=name, req_id=req.req_id)
        if st.is_checkable(req) and not st.check_observations(req.req_id):
            # 検査できる要件への印は、その要件の検査を一度走らせた後（不確定だった時）だけ。先に印を付けて検査を省くと、
            # 認証壁の要件に NEEDS_AUTH を付けるような「不適合の洗浄」ができてしまう（S-03）。結論つきの観測があれば ALREADY_DECIDED
            return self._deny(PolicyId.UNVERIF, "CHECK_FIRST", name=name, req_id=req.req_id)
        if st.calls_used(req.req_id) >= self.meter.caps.tool_calls_per_requirement:
            return self._deny(PolicyId.BUDGET_CALLS, "REQ_CAP", name=name, req_id=req.req_id)
        if code in (UnverifiableReason.NEEDS_AUTH, UnverifiableReason.NEEDS_JS) and self._premise(call) is None:
            return self._deny(PolicyId.UNVERIF, "NO_PREMISE", name=name, req_id=req.req_id)
        return None

    def _premise(self, call: ToolCall) -> str | None:
        """NEEDS_AUTH は提出URLの認証壁の観測、NEEDS_JS は提出URLの spa_shell の観測（最新の1件）が前提。"""
        if call.name is not ToolName.MARK_UNVERIFIABLE:
            return None
        want = {UnverifiableReason.NEEDS_AUTH: ObsCode.AUTH_WALL, UnverifiableReason.NEEDS_JS: ObsCode.SPA_SHELL}.get(
            call.args.reason_code  # type: ignore[union-attr]
        )
        if want is None:
            return None
        for o in reversed(self.state.probes()):
            if o.facts.get("target") == "SUBMISSION_URL" and o.code is want:
                return o.obs_id
        return None

    # ---- 取得の計上（ツールが呼ぶ）-------------------------------------------------------------
    def charge_fetches(self, kind: FetchKind, n: int, href: str) -> None:
        origin = self._third_party_origin(href)
        for _ in range(max(1, n)):
            self.meter.budget.charge_fetch(origin, kind)
