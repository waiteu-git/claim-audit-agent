"""引用検証器の本体: RawRequirement を VerifiedRequirement へ昇格させる／推測へ降格させる（設計 §5-1 型分離・最終再検証）。

VerificationSeal を発行するのはこのモジュールだけ（tests/test_layout.py が固定）。印が無いと VerifiedRequirement は
作れないので、「検証前の型（RawRequirement）」と「検証後の型」は混同できない。

Reader の再引用は1回だけ。流れは次のとおりで、T6（Reader）はモデル呼び出しだけを担当する:

    out = checker.begin(raw, "R3")            # 1回目の引用を照合
    if out.needs_requote:                     # 言い換え・省略・複数ブロックなどで棄却された
        new_quote = await reader.requote(out.reject_reason)   # 理由コードだけを渡す（原文は渡さない）
        out = checker.finish(out.pending, new_quote)
    req, steps = out.requirement, out.steps   # steps をそのまま quote_check イベントへ載せる

昇格・降格の結果はすべて VerifiedRequirement（kind・降格理由・チップ付き）で、推測へ落ちた要件も同じ型で持つ。
"""
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pydantic import ValidationError

from app.contracts import (
    QUOTE_SPAN_MAX_CHARS,
    REASON_MAX_CHARS,
    DemotionReason,
    Kind,
    QuoteRejectReason,
    QuoteStep,
    QuoteStepOutcome,
    RawRequirement,
    UnverifiedSerializationError,
    VerificationSeal,
    VerifiedRequirement,
    VerifiedSpan,
)
from app.quotes.index import DocIndex, Rejected, Verified
from app.quotes.semantics import Decision, decide
from app.quotes.sentence import snap_to_sentence
from app.textsafe import BLOCK_SEP, escape_for_display, strip_unsafe

_SEAL = VerificationSeal.issue("app.quotes")

# 再引用を頼んでも意味が無い棄却。注入疑い区間と重なった引用は、言い直させず推測へ落として警告に回す（P-INJ-01）。
_NO_REQUOTE = frozenset({QuoteRejectReason.INJECTION_OVERLAP})


def _digest(quote: str) -> str:
    return hashlib.sha256(quote.encode("utf-8", "backslashreplace")).hexdigest()[:16]


def _clean_gist(s: str) -> str:
    """非信頼の言い換え。表示に使えるよう、安全でない文字・境界・改行を落として140字に切る。"""
    s = strip_unsafe(s).replace(BLOCK_SEP, " ").replace("\n", " ").replace("\t", " ")
    return " ".join(s.split())[:REASON_MAX_CHARS]


def _rejected_step(attempt: int, reason: QuoteRejectReason, quote: str) -> QuoteStep:
    shown = escape_for_display(quote, QUOTE_SPAN_MAX_CHARS)  # ゼロ幅・bidi・タグ文字を \u{..} 表記にする
    return QuoteStep(
        attempt=attempt,
        outcome=QuoteStepOutcome.REJECTED,
        reason_code=reason.value,
        model_quote=shown or None,
        quote_digest=_digest(quote),
    )


def _step(attempt: int, outcome: QuoteStepOutcome, quote: str, reason: str | None = None) -> QuoteStep:
    return QuoteStep(attempt=attempt, outcome=outcome, reason_code=reason, quote_digest=_digest(quote))


@dataclass(frozen=True, slots=True)
class PendingRequote:
    """1回目の引用が棄却され、再引用を待っている要件。finish() に渡す。"""

    raw: RawRequirement
    req_id: str
    first_reason: QuoteRejectReason
    steps: tuple[QuoteStep, ...]


@dataclass(frozen=True, slots=True)
class QuoteOutcome:
    """引用検証の結果。requirement が確定、または pending（再引用待ち）のどちらか。"""

    requirement: VerifiedRequirement | None
    steps: tuple[QuoteStep, ...]
    pending: PendingRequote | None = None
    reject_reason: QuoteRejectReason | None = None  # 直近の棄却理由。無ければ None（P-INJ-01 の発火などに使う）

    @property
    def needs_requote(self) -> bool:
        return self.pending is not None


class ReverifyFailure(StrEnum):
    DOC_MISSING = "doc_missing"  # 文書が索引に無い
    SPAN_RANGE = "span_range"  # 位置が原文の外
    TEXT_MISMATCH = "text_mismatch"  # 原文のその位置の文字列が、持っている引用と違う
    INJECTION_OVERLAP = "injection_overlap"  # 注入疑いの区間と重なっている
    NOT_A_SENTENCE = "not_a_sentence"  # 1文の区間でない（拡張の結果として作られた区間ではない）／セル区切りをまたぐ
    KIND_INCONSISTENT = "kind_inconsistent"  # 引用から再計算した kind・降格・チップが記録と違う
    INVARIANT = "invariant"  # 契約の不変条件を満たさない（検証を迂回して作られた疑い）
    NOT_ISSUED = "not_issued"  # この検証器が出した内容と違う（降格された要件を書き換えて昇格させた疑い）


@dataclass(frozen=True, slots=True)
class ReverifyIssue:
    req_id: str
    reason: ReverifyFailure


@dataclass(frozen=True, slots=True)
class ReverifyResult:
    """最終再検証の結果。requirements は不合格を「引用なしの推測」へ落とし、合格に印（reverified）を付けたもの。"""

    requirements: tuple[VerifiedRequirement, ...]
    issues: tuple[ReverifyIssue, ...]

    @property
    def ok(self) -> bool:
        return not self.issues


def _fingerprint(req: VerifiedRequirement) -> tuple:
    """検証器が出した要件の中身（引用の判定に効く欄だけ。reverified・gist と、後段が付け直しうる check_class・slot は含めない）。"""
    sp = req.span
    return (
        req.kind,
        req.declared_kind,
        req.demotion,
        req.chips,
        (sp.doc_id, sp.start, sp.end, sp.original_span) if sp is not None else None,
    )


def _span_key(req: VerifiedRequirement) -> tuple | None:
    sp = req.span
    return (sp.doc_id, sp.start, sp.end, sp.original_span, req.declared_kind) if sp is not None else None


def _outcome(req: VerifiedRequirement) -> tuple:
    return (req.kind, req.demotion, req.chips)


class QuoteChecker:
    def __init__(self, index: DocIndex) -> None:
        self.index = index
        # この検証器が出した要件の記録。最終再検証で、出した内容のままかを確かめる。
        # 文の中の否定が引用の外にあって降格された要件を、model_copy で「必須・降格なし」へ書き換えると、文全体を引用として
        # 再計算する側では否定が「引用の内側」になって通ってしまう（引用の区間は記録に残らない）。それを塞ぐ。
        #   - req_id ごとの記録: 同じ req_id の要件は、出した内容のどれかと一致しなければならない
        #   - 区間ごとの記録: req_id を付け替えても、同じ文（文書・位置・申告の kind）に出した結果のどれかでなければならない
        # 記録の無い要件（別の検証器で復元した要件・見たことの無い区間）は、これまでどおり原文との突き合わせだけで判定する。
        self._issued: dict[str, set[tuple]] = {}
        self._issued_spans: dict[tuple, set[tuple]] = {}

    def _record(self, req: VerifiedRequirement) -> VerifiedRequirement:
        self._issued.setdefault(req.req_id, set()).add(_fingerprint(req))
        key = _span_key(req)
        if key is not None:
            self._issued_spans.setdefault(key, set()).add(_outcome(req))
        return req

    # ---- 昇格・降格 ---------------------------------------------------------------------------
    def begin(self, raw: RawRequirement, req_id: str) -> QuoteOutcome:
        """1回目の引用を照合する。棄却されて再引用の余地があれば pending 付きで返す。"""
        if not isinstance(raw, RawRequirement):
            # 検証済みの型を再び検証へ流さない（型の取り違えを実行時にも止める）
            raise TypeError(f"RawRequirement だけを受け付けます: {type(raw).__name__}")
        res = self.index.verify(raw.quote)
        if isinstance(res, Verified):
            return self._promote(raw, req_id, res, 1, ())
        steps = (_rejected_step(1, res.reason, raw.quote),)
        if raw.kind is Kind.SPECULATIVE or res.reason in _NO_REQUOTE:
            # 推測と申告された要件に引用は要らない。再引用を頼まず、引用なしの推測として確定する
            return self._unverified(raw, req_id, steps, 1, res.reason)
        return QuoteOutcome(None, steps, PendingRequote(raw, req_id, res.reason, steps), res.reason)

    def finish(self, pending: PendingRequote, requote: str | None) -> QuoteOutcome:
        """再引用（無ければ None）を照合する。合格しなければ推測へ降格する。再々引用は無い。"""
        quote = requote or ""
        res = self.index.verify(quote) if quote.strip() else Rejected(QuoteRejectReason.EMPTY)
        if isinstance(res, Verified):
            return self._promote(pending.raw, pending.req_id, res, 2, pending.steps)
        steps = (*pending.steps, _rejected_step(2, res.reason, quote))
        return self._unverified(pending.raw, pending.req_id, steps, 2, res.reason)

    def resolve(self, raw: RawRequirement, req_id: str, requote: str | None = None) -> QuoteOutcome:
        """begin と finish をまとめて行う（再引用が手元にある時・テスト用）。"""
        out = self.begin(raw, req_id)
        return self.finish(out.pending, requote) if out.pending is not None else out

    def _promote(
        self, raw: RawRequirement, req_id: str, v: Verified, attempt: int, prior: tuple[QuoteStep, ...]
    ) -> QuoteOutcome:
        # 出現が複数（同じ文書に2〜3回、または複数の文書に）のときは、全出現を見て最も慎重な判定を採り、その出現の文を表示する。
        # 出典は登録順で先頭の文書だが、例外が付くのは後ろの文書の同じ文かもしれない（LP は無条件、FAQ は「ただし」付き）。
        # 同じ重さなら先頭（登録順の前）を採る。
        best: Decision | None = None
        best_doc = v.doc_id
        best_occ = v.occurrences
        groups = ((v.doc_id, v.spans, v.occurrences), *((o.doc_id, o.spans, o.occurrences) for o in v.others))
        for doc_id, spans, occ in groups:
            text = self.index.text(doc_id)
            barriers = self.index.barriers(doc_id)
            for a, b in spans:
                d = decide(text, a, b, raw.kind, barriers)
                if best is None or d.severity > best.severity:
                    best, best_doc, best_occ = d, doc_id, occ
        assert best is not None
        text = self.index.text(best_doc)
        s, e = best.span
        span = VerifiedSpan(doc_id=best_doc, start=s, end=e, original_span=text[s:e], occurrences=best_occ)
        req = self._record(
            VerifiedRequirement(
                seal=_SEAL,
                req_id=req_id,
                kind=best.kind,
                declared_kind=raw.kind,
                check_class=raw.check_class,
                slot=raw.slot,
                span=span,
                demotion=best.demotion,
                chips=best.chips,
            )
        )
        steps = [*prior, _step(attempt, QuoteStepOutcome.VERIFIED, raw.quote)]
        if best.demotion is not None:
            steps.append(_step(attempt, QuoteStepOutcome.DEMOTED, raw.quote, best.demotion.value))
        return QuoteOutcome(req, tuple(steps))

    def _unverified(
        self, raw: RawRequirement, req_id: str, steps: tuple[QuoteStep, ...], attempt: int, reason: QuoteRejectReason
    ) -> QuoteOutcome:
        req = self._record(
            VerifiedRequirement(
                seal=_SEAL,
                req_id=req_id,
                kind=Kind.SPECULATIVE,
                declared_kind=raw.kind,
                check_class=raw.check_class,
                slot=raw.slot,
                span=None,
                demotion=DemotionReason.QUOTE_UNVERIFIED,
                gist=_clean_gist(raw.gist),
            )
        )
        steps = (*steps, _step(attempt, QuoteStepOutcome.DEMOTED, raw.quote, DemotionReason.QUOTE_UNVERIFIED.value))
        return QuoteOutcome(req, steps, None, reason)

    # ---- 最終再検証 ---------------------------------------------------------------------------
    def reverify(self, requirements: Sequence[VerifiedRequirement]) -> ReverifyResult:
        """レポート確定直前に、全引用をもう一度 DocStore の原文に当てる（Gate2 条件②の保証の本体）。

        型で未検証を弾いても、model_copy は検証を通さずに値を書き換えられる。ここで原文と突き合わせて確かめる:
        文書が在る・位置が原文の中・その位置の文字列が記録と一致・セル区切りをまたがない・注入疑いに重ならない・1文の区間・
        引用から再計算した kind が記録と一致・契約の不変条件・この検証器が出した内容と一致（記録がある場合）。
        不合格は「引用なしの推測」へ落とし、issues に理由を残す。

        引用の区間は記録に残らないので、引用の外の否定・例外による降格は再計算できない（文全体を引用として再計算すると、
        否定語が引用の内側になる）。降格された要件を書き換えて昇格させる偽造は、発行の記録（NOT_ISSUED）で塞ぐ。
        """
        out: list[VerifiedRequirement] = []
        issues: list[ReverifyIssue] = []
        for req in requirements:
            if not isinstance(req, VerifiedRequirement):
                raise UnverifiedSerializationError(f"未検証の型は再検証できません: {type(req).__name__}")
            failure = self._check_one(req)
            if failure is None and req.span is not None and self._not_issued(req):
                failure = ReverifyFailure.NOT_ISSUED
            if failure is None:
                out.append(req.mark_reverified(_SEAL))
            else:
                issues.append(ReverifyIssue(req.req_id, failure))
                out.append(
                    VerifiedRequirement(
                        seal=_SEAL,
                        req_id=req.req_id,
                        kind=Kind.SPECULATIVE,
                        declared_kind=req.declared_kind,
                        check_class=req.check_class,
                        slot=req.slot,
                        span=None,
                        demotion=DemotionReason.QUOTE_UNVERIFIED,
                    )
                )
        return ReverifyResult(tuple(out), tuple(issues))

    def _not_issued(self, req: VerifiedRequirement) -> bool:
        """この検証器が出した内容と違う（同じ req_id、または同じ文に出した結果のどれとも一致しない）。記録の無い要件は判定しない。"""
        by_id = self._issued.get(req.req_id)
        if by_id is not None and _fingerprint(req) not in by_id:
            return True
        key = _span_key(req)
        by_span = self._issued_spans.get(key) if key is not None else None
        return by_span is not None and _outcome(req) not in by_span

    def _check_one(self, req: VerifiedRequirement) -> ReverifyFailure | None:
        try:
            VerifiedRequirement.restore(req.model_dump(), seal=_SEAL)  # 契約の不変条件を作り直して確かめる
        except ValidationError:
            return ReverifyFailure.INVARIANT
        sp = req.span
        if sp is None:
            return None  # 引用を主張していない（引用なしの推測）。照合するものが無い
        if not self.index.has_doc(sp.doc_id) or not self.index.is_usable(sp.doc_id):
            return ReverifyFailure.DOC_MISSING
        text = self.index.text(sp.doc_id)
        if not 0 <= sp.start < sp.end <= len(text):
            return ReverifyFailure.SPAN_RANGE
        if text[sp.start : sp.end] != sp.original_span:
            return ReverifyFailure.TEXT_MISMATCH
        if self.index.crosses_separator(sp.doc_id, sp.start, sp.end):
            return ReverifyFailure.NOT_A_SENTENCE  # 検証時は crosses_block で棄却される区間（表のセル・ブロックをまたぐ）
        barriers = self.index.barriers(sp.doc_id)
        if any(sp.start < be and bs < sp.end for bs, be in barriers):
            return ReverifyFailure.INJECTION_OVERLAP
        if req.declared_kind is Kind.SPECULATIVE:
            return None  # 推測と申告された要件は、原文に在ることだけを確かめれば足りる
        if req.demotion is DemotionReason.SENTENCE_TOO_LONG:
            # span は拡張前の引用。その文が実際に160字を超えることを確かめる
            s, e = snap_to_sentence(text, sp.start, sp.end, barriers)
            return None if e - s > QUOTE_SPAN_MAX_CHARS else ReverifyFailure.KIND_INCONSISTENT
        if snap_to_sentence(text, sp.start, sp.end, barriers) != (sp.start, sp.end):
            return ReverifyFailure.NOT_A_SENTENCE
        if req.demotion is DemotionReason.NEGATION_OR_EXCEPTION:
            return None  # 引用の区間が残っていないので、否定語の位置関係は再計算できない
        # 引用＝文として再計算する。降格しなかった要件は、この条件でも降格しない（文の外の語は引用時に見ている）
        d = decide(text, sp.start, sp.end, req.declared_kind, barriers)
        if d.kind is not req.kind or d.demotion is not req.demotion or d.chips != req.chips:
            return ReverifyFailure.KIND_INCONSISTENT
        return None
