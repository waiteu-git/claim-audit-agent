"""DocIndex: 文書の正規化テキストと、原文オフセットの復元表を持ち、引用の逐語照合を行う（設計 §5-1）。

原則: 出典（文書・位置）はモデルの申告でなくコードの検索結果。モデルが出すのは引用文字列だけで、doc_id・位置は読まない。
索引にあるのは spec 文書の可視テキストだけ。次のものは索引に無いので、そこからは引用できない:
  - 注入疑いで置換した区間（〔注入疑い〕。位置は barriers として持ち、一致が重なれば INJECTION_OVERLAP で拒否する）
  - 隠しチャネル（SanitizedDoc は本文を持たない）
  - submission 文書（検査される側の自己申告。要件の出典にさせると、提出物が自分で「必須」と書けてしまう）
ブロック境界（U+001E）と markdown の表のセル区切り（| ｜）をまたぐ引用は crosses_block で拒否する（隣接セルの縫合を防ぐ）。

ここが返す Verified は「引用が原文に逐語（NFKC・空白差を除く）で実在する」ことだけを意味する。
1文への拡張・否定語・kind の判定は semantics.py、VerifiedRequirement への昇格は checker.py。
"""
import unicodedata
from bisect import bisect_left
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.contracts import QUOTE_SPAN_MAX_CHARS, DocRole, QuoteRejectReason, SanitizedDoc
from app.quotes import vocab
from app.quotes.normalize import CELL_SEPARATORS, Normalized, normalize
from app.quotes.sentence import Barrier
from app.textsafe import BLOCK_SEP

MIN_QUOTE_CHARS = 6  # 正規化後。これ未満は証拠にならない
SHORT_QUOTE_MAX_CHARS = 11  # 6〜11字は、出現1回かつ義務・任意・数値語を含む時だけ
MAX_QUOTE_CHARS = QUOTE_SPAN_MAX_CHARS  # 正規化後160字まで
AMBIGUOUS_MIN_OCCURRENCES = 4  # 同一文書で4回以上出現したら、どれを指すか決められない
MAX_RAW_QUOTE_CHARS = 2000  # これを超える入力は正規化せずに拒否する（RawRequirement は600字まで）
_HIT_CAP = 16  # 数え上げの上限（4回で ambiguous なので、それ以上は数えても意味が無い）
_FIND_CAP = 20000  # str.find の回数の上限（同じ文字が続く巨大な文書や、結合文字だらけの文書で時間を使い切らない）
_SPAN_SCAN_CAP = QUOTE_SPAN_MAX_CHARS * 4  # 原文区間がこれを超える一致は中身を見ない


@dataclass(frozen=True, slots=True)
class DocHits:
    """ある文書での、使える一致の全出現（拡張前の区間）と、その文書での出現数。"""

    doc_id: str
    spans: tuple[tuple[int, int], ...]
    occurrences: int


@dataclass(frozen=True, slots=True)
class Verified:
    """引用の逐語一致（設計の Verified）。start/end は原文（visible_text）上の位置で、1文への拡張前。

    spans は一致した全出現（出現が2〜3回のとき、否定語の判定は全出現にかける）。start/end はその最初。
    others は、先頭の文書より後ろの文書にある一致（同じ文が LP と FAQ の両方にあるとき、例外が付くのは後ろの方かもしれない。
    出典は先頭の文書でも、否定・例外の判定は全文書の出現にかける。敵対レビュー W9）。
    """

    doc_id: str
    start: int
    end: int
    original_span: str
    occurrences: int
    spans: tuple[tuple[int, int], ...] = field(default=())
    others: tuple[DocHits, ...] = field(default=())


@dataclass(frozen=True, slots=True)
class Rejected:
    reason: QuoteRejectReason
    occurrences: int = 0  # 見つかった出現数（ambiguous・short_not_allowed の診断用）


@dataclass(frozen=True, slots=True)
class _Entry:
    doc_id: str
    text: str
    flat: Normalized
    seps: tuple[int, ...]  # ブロック境界 U+001E と、表のセル区切り（| ｜）の位置
    barriers: tuple[Barrier, ...]  # 注入疑いで置換した区間（可視）


@dataclass(slots=True)
class _Scan:
    ok: list[tuple[int, int]] = field(default_factory=list)
    total: int = 0
    crossing: int = 0
    injected: int = 0
    too_long: int = 0


def _ascii_alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def _is_ascii_digit(c: str) -> bool:
    return c in "0123456789"


def _is_super_or_sub(ch: str) -> bool:
    return unicodedata.decomposition(ch).startswith(("<super>", "<sub>"))


def _aligned(flat: Normalized, p: int, n: int) -> bool:
    """一致の両端が、原文のクラスタの境界にある（結合文字や互換文字の途中から始まったり終わったりしない）。"""
    if p > 0 and flat.starts[p] == flat.starts[p - 1]:
        return False
    q = p + n
    return not (q < len(flat.text) and flat.starts[q] == flat.starts[q - 1])


_OPERATORS = frozenset("<>=")


def _token_boundary_ok(flat: Normalized, p: int, n: int) -> bool:
    """数・英単語・比較演算子の途中から始まり/途中で終わる一致を拒否する（「3分」が「13分」「1.5分」に、「=5」が「>=5」に一致しない）。"""
    t, g = flat.text, flat.gap_after
    if p > 0 and not g[p - 1]:
        c0, pc = t[p], t[p - 1]
        if _ascii_alnum(c0) and _ascii_alnum(pc):
            return False
        if c0 in _OPERATORS and pc in _OPERATORS:
            return False
        if _is_ascii_digit(c0) and pc in ".," and p > 1 and not g[p - 2] and _is_ascii_digit(t[p - 2]):
            return False
    q = p + n
    if q < len(t) and not g[q - 1]:
        cl, nc = t[q - 1], t[q]
        if _ascii_alnum(cl) and _ascii_alnum(nc):
            return False
        if cl in _OPERATORS and nc in _OPERATORS:
            return False
        if _is_ascii_digit(cl) and nc in ".," and q + 1 < len(t) and not g[q] and _is_ascii_digit(t[q + 1]):
            return False
    return True


def _same_run(a: str, b: str) -> bool:
    """空白の有無が意味を変える並び: 英字どうし（no table / notable）、数字どうし（1 0 / 10）、数字と小数点・桁区切り（2. 0 / 2.0）。
    数字と英字（5 MB / 5MB）は空白があっても同じ意味。"""
    if not (a.isascii() and b.isascii()):
        return False
    if a.isalpha() and b.isalpha():
        return True
    return (a.isdigit() and (b.isdigit() or b in ".,")) or (b.isdigit() and a in ".,")


def _spacing_ok(flat: Normalized, p: int, nq: Normalized) -> bool:
    """ASCII の英字どうし・数字どうしの間の空白の有無が、引用と原文で同じ（空白を除く正規化が別の語に一致させない）。"""
    q = nq.text
    for k in range(len(q) - 1):
        if _same_run(q[k], q[k + 1]) and flat.gap_after[p + k] != nq.gap_after[k]:
            return False
    return True


def _compat_chars_ok(text: str, os_: int, oe: int, raw_quote: str) -> bool:
    """上付き・下付き文字（10² と 102）は、NFKC が同じ字にしてしまう。数の意味が変わるので、原文と引用で同じ字だけ許す。"""
    in_doc = {c for c in text[os_:oe] if _is_super_or_sub(c)}
    in_quote = {c for c in raw_quote if _is_super_or_sub(c)}
    return in_doc == in_quote


def _is_elided(quote: str) -> bool:
    return bool(vocab.ELLIPSIS_RAW.search(quote) or vocab.ELLIPSIS_AFTER_NFKC.search(unicodedata.normalize("NFKC", quote)))


# 拒否理由の優先順。文書ごとの結果を束ねる時、「在るが使えない」ほど具体的な理由を採る。
_REASON_PRIORITY = (
    QuoteRejectReason.INJECTION_OVERLAP,
    QuoteRejectReason.CROSSES_BLOCK,
    QuoteRejectReason.AMBIGUOUS,
    QuoteRejectReason.SHORT_NOT_ALLOWED,
    QuoteRejectReason.TOO_LONG,
    QuoteRejectReason.NOT_FOUND,
)


class DocIndex:
    """spec 文書の索引。文書は SanitizedDoc（T4 の出力）。"""

    def __init__(self, docs: Iterable[SanitizedDoc]) -> None:
        self._entries: dict[str, _Entry] = {}
        for d in docs:
            if d.role is not DocRole.SPEC:
                continue
            if d.doc_id in self._entries:
                raise ValueError(f"doc_id が重複しています: {d.doc_id}")
            text = d.visible_text
            seps = tuple(i for i, c in enumerate(text) if c == BLOCK_SEP or c in CELL_SEPARATORS)
            barriers = tuple(sorted((s.start, s.end) for s in d.injection_signals if s.visible and s.start is not None and s.end is not None))
            self._entries[d.doc_id] = _Entry(d.doc_id, text, normalize(text), seps, barriers)

    @property
    def doc_ids(self) -> tuple[str, ...]:
        return tuple(self._entries)

    def has_doc(self, doc_id: str) -> bool:
        return doc_id in self._entries

    def text(self, doc_id: str) -> str:
        return self._entries[doc_id].text

    def barriers(self, doc_id: str) -> tuple[Barrier, ...]:
        return self._entries[doc_id].barriers

    def crosses_separator(self, doc_id: str, start: int, end: int) -> bool:
        """[start, end) の中にブロック境界・表のセル区切りがある（検証時は crosses_block で棄却される区間）。"""
        seps = self._entries[doc_id].seps
        i = bisect_left(seps, start)
        return i < len(seps) and seps[i] < end

    def is_usable(self, doc_id: str) -> bool:
        """正規化の自己検査（クラスタ分割と全体の NFKC が一致）を通った文書。通らなければ何も照合できない。"""
        return self._entries[doc_id].flat.consistent

    # ---- 照合 ---------------------------------------------------------------------------------
    def verify(self, quote: str, doc_id: str | None = None) -> Verified | Rejected:
        """引用を照合する。doc_id を渡すとその文書だけ、省略すると全 spec 文書（登録順）から探す。

        Reader が申告する doc_id・位置は使わない（呼び出し側が渡さない）。出典は検索結果の最初に合格した文書。
        """
        if len(quote) > MAX_RAW_QUOTE_CHARS:
            return Rejected(QuoteRejectReason.TOO_LONG)
        stripped = quote.strip()  # str.strip は U+001E も空白として落とす（両端の境界は引用の一部ではない）
        inner_sep = BLOCK_SEP in stripped
        nq = normalize(stripped)
        n = len(nq.text)
        if n == 0:
            return Rejected(QuoteRejectReason.EMPTY)
        if not nq.consistent:
            return Rejected(QuoteRejectReason.NOT_FOUND)
        if _is_elided(stripped):
            return Rejected(QuoteRejectReason.ELIDED)
        if n < MIN_QUOTE_CHARS:
            return Rejected(QuoteRejectReason.TOO_SHORT)
        if n > MAX_QUOTE_CHARS:
            return Rejected(QuoteRejectReason.TOO_LONG)
        short_ok = n > SHORT_QUOTE_MAX_CHARS or vocab.has_short_quote_word(nq.text, normalize(stripped, spaced=True).text)

        if doc_id is not None:
            entry = self._entries.get(doc_id)
            entries: Sequence[_Entry] = (entry,) if entry is not None else ()
        else:
            entries = tuple(self._entries.values())

        reasons: dict[QuoteRejectReason, int] = {}  # 理由 → その時の出現数（診断用）
        any_hit = False
        found: tuple[_Entry, _Scan] | None = None  # 出典にする文書（登録順で最初に合格した文書）
        others: list[DocHits] = []  # それより後ろの文書の合格した一致（否定・例外の判定だけに使う）
        for entry in entries:
            sc = self._scan(entry, nq, stripped)
            any_hit = any_hit or sc.total > 0
            if sc.ok:
                if sc.total >= AMBIGUOUS_MIN_OCCURRENCES:
                    reasons[QuoteRejectReason.AMBIGUOUS] = sc.total
                elif n <= SHORT_QUOTE_MAX_CHARS and (sc.total != 1 or not short_ok):
                    reasons[QuoteRejectReason.SHORT_NOT_ALLOWED] = sc.total
                elif inner_sep:
                    reasons[QuoteRejectReason.CROSSES_BLOCK] = sc.total
                elif found is None:
                    found = (entry, sc)
                else:
                    others.append(DocHits(entry.doc_id, tuple(sc.ok), sc.total))
            if sc.injected:
                reasons.setdefault(QuoteRejectReason.INJECTION_OVERLAP, sc.injected)
            if sc.crossing:
                reasons.setdefault(QuoteRejectReason.CROSSES_BLOCK, sc.crossing)
            if sc.too_long:
                reasons.setdefault(QuoteRejectReason.TOO_LONG, sc.too_long)
        if found is not None:
            entry, sc = found
            a, b = sc.ok[0]
            return Verified(entry.doc_id, a, b, entry.text[a:b], sc.total, tuple(sc.ok), tuple(others))
        if inner_sep and any_hit:
            # 引用に境界が入っている＝複数のブロックにまたがると自分で言っている
            return Rejected(QuoteRejectReason.CROSSES_BLOCK, reasons.get(QuoteRejectReason.CROSSES_BLOCK, 0))
        for r in _REASON_PRIORITY:
            if r in reasons:
                return Rejected(r, reasons[r])
        return Rejected(QuoteRejectReason.NOT_FOUND)

    def _scan(self, entry: _Entry, nq: Normalized, raw_quote: str) -> _Scan:
        flat = entry.flat
        sc = _Scan()
        if not flat.consistent:
            return sc
        q, n = nq.text, len(nq.text)
        p = flat.text.find(q)
        finds = 0
        while p != -1 and sc.total < _HIT_CAP and finds < _FIND_CAP:
            finds += 1
            if _aligned(flat, p, n) and _token_boundary_ok(flat, p, n) and _spacing_ok(flat, p, nq):
                os_, oe = flat.starts[p], flat.ends[p + n - 1]
                if oe - os_ > _SPAN_SCAN_CAP:
                    sc.total += 1
                    sc.too_long += 1
                elif _compat_chars_ok(entry.text, os_, oe, raw_quote):
                    sc.total += 1
                    i = bisect_left(entry.seps, os_)
                    if any(os_ < be and bs < oe for bs, be in entry.barriers):
                        sc.injected += 1
                    elif i < len(entry.seps) and entry.seps[i] < oe:
                        sc.crossing += 1
                    elif oe - os_ > MAX_QUOTE_CHARS:
                        sc.too_long += 1
                    else:
                        sc.ok.append((os_, oe))
            p = flat.text.find(q, p + 1)
        return sc
