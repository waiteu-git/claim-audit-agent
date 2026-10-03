"""引用照合用の正規化と、正規化後の位置から原文の位置を復元する表（設計 §5-1）。

規則の出発点は vq.py（NFKC → 空白・Cf・制御文字・markdown記号を除去 → 部分一致。390件の実引用で検証済み）。
緩めない。締める点だけ足している:

  - ブロック境界 U+001E は除去しない（str.isspace() は U+001E を真と判定するので、素朴に書くと境界が消える）。
    正規化の出力には載せず、位置を DocIndex が別に持って crosses_block を判定する。
  - ">" と "#" は行頭だけ除去する。文中の ">" は比較演算子（"x>=5" と "x=5" を衝突させない）、
    "#" は "C#" のように意味を持つ。"*" "\\" "|" "`" "_" は従来どおり常に除去する。
  - 不可視文字は Cf・Cc に加えて、結合書記素ジョイナ・異体字セレクタ・ハングルの埋め字なども除去する
    （見た目が同じ引用を通すため。表示には使わない＝画面に出るのは原文から切り出した文字列だけ）。

オフセット復元の仕組み: 原文を「NFKC の結果が独立に決まる最小のかたまり（クラスタ）」に分け、クラスタごとに
NFKC をかけて、出力した各文字へクラスタの原文区間 [start, end) を対応づける。半角カナ＋濁点（ｶﾞ → ガ）や
結合文字（か＋U+3099 → が）は、1文字ずつ NFKC をかけると全体にかけた結果と食い違うので、必ず同じクラスタに入れる。
"""
import unicodedata
from array import array
from dataclasses import dataclass
from functools import lru_cache

from app.textsafe import BLOCK_SEP

# 常に除去する markdown 記号。
ALWAYS_DROP = frozenset("*\\|`_")
# 行頭だけ除去する markdown 記号（引用符・見出し）。">=" は比較演算子なので、行頭でも除去しない。
LINE_START_DROP = frozenset(">#")
# 除去するが、表のセルの区切りとして働く記号（空白と同じ「語の切れ目」に数える。位置は DocIndex が境界として持つ）。
CELL_SEPARATORS = frozenset("|｜")
# 行頭に戻す文字。
_LINE_BREAKS = frozenset({"\n", "\r", " ", " ", "\x0b", "\x0c", "\x85", BLOCK_SEP})
# Cf・Cc に入らないが、画面に何も出ない文字。
_EXTRA_IGNORABLE = frozenset({0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0})
# ハングルの字母（V・T が前の字母と合成される）。インデックスでは非 inert にして必ず NFKC の検査へ回す。
_JAMO_RANGES = ((0x1100, 0x11FF), (0xA960, 0xA97F), (0xD7B0, 0xD7FF))
# 結合しうる文字が1クラスタに延々と続く入力（Zalgo）で NFKC の検査が二乗にならないよう、
# この長さを超えたら非 inert の文字は検査せず取り込む（クラスタが大きくなるだけで、正しさは変わらない）。
_CLUSTER_SOFT_CAP = 32


def _nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


@lru_cache(maxsize=65536)
def _inert(ch: str) -> bool:
    """この文字は、直前の文字と合成も並べ替えもされない（必ず新しいクラスタの先頭になる）。"""
    o = ord(ch)
    if o < 0x80:  # ASCII は結合先にならない
        return True
    if unicodedata.category(ch) in ("Mn", "Mc", "Me") or unicodedata.combining(ch):
        return False
    if any(a <= o <= b for a, b in _JAMO_RANGES):
        return False
    return unicodedata.is_normalized("NFKC", ch)


@lru_cache(maxsize=65536)
def _is_starter(ch: str) -> bool:
    """NFKD にした先頭が結合クラス0（直前の文字の後ろに並べ替えで入り込まない文字）。ｶﾞ の ﾞ（→ U+3099）は偽。"""
    return unicodedata.combining(unicodedata.normalize("NFKD", ch)[0]) == 0


def clusters(text: str) -> list[tuple[int, int]]:
    """NFKC が独立に決まる最小のかたまり [start, end) の列。

    結合クラスを持つ文字（濁点・アクセントなど）は、後ろの文字との並べ替えで前の結合文字を追い越しうるので、
    検査で分けられるように見えても必ず前のクラスタに取り込む。分けてよいのは「先頭が非結合の文字」だけ。
    """
    n = len(text)
    out: list[tuple[int, int]] = []
    start = 0
    while start < n:
        end = start + 1
        while end < n:
            c = text[end]
            if _inert(c):
                break
            if end - start < _CLUSTER_SOFT_CAP and _is_starter(c):
                head = text[start:end]
                # 結合も並べ替えも起きない（分けても結果が同じ）なら、ここでクラスタを閉じる
                if _nfkc(head + c) == _nfkc(head) + _nfkc(c):
                    break
            end += 1
        out.append((start, end))
        start = end
    return out


def _is_ignorable(ch: str) -> bool:
    if unicodedata.category(ch) in ("Cf", "Cc"):
        return True
    o = ord(ch)
    return o in _EXTRA_IGNORABLE or 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF


@dataclass(frozen=True, slots=True)
class Normalized:
    """正規化の結果。text の i 文字目は、原文の [starts[i], ends[i]) のクラスタから出た。

    gap_after[i] は、i 文字目と次の文字の間に空白（改行・ブロック境界を含む）があったか。
    ASCII の語の区切り（"no table" と "notable" を区別する）に使う。
    consistent が偽なら、クラスタ分割と全体への NFKC が食い違った（起きない想定。起きたら照合に使わない）。
    """

    text: str
    starts: array
    ends: array
    gap_after: bytes
    consistent: bool = True

    def __len__(self) -> int:
        return len(self.text)


def normalize(text: str, *, spaced: bool = False) -> Normalized:
    """正規化する。spaced=False は空白を全部除去した照合用、True は空白を1つに畳み小文字にした語の走査用。"""
    out: list[str] = []
    starts = array("I")
    ends = array("I")
    gaps = bytearray()
    parts: list[str] = []
    at_line_start = True
    for cs, ce in clusters(text):
        raw = text[cs:ce]
        nf = raw if (ce - cs == 1 and ord(raw) < 0x80) else _nfkc(raw)
        parts.append(nf)
        for ch in nf:
            if ch in _LINE_BREAKS or ch.isspace():
                if ch in _LINE_BREAKS:
                    at_line_start = True
                if spaced:
                    if out and out[-1] != " ":
                        out.append(" ")
                        starts.append(cs)
                        ends.append(ce)
                        gaps.append(0)
                elif out:
                    gaps[-1] = 1
                continue
            if ch == "|":
                if not spaced and out:
                    gaps[-1] = 1
                continue
            if _is_ignorable(ch) or ch in ALWAYS_DROP:
                continue
            if ch in LINE_START_DROP and at_line_start and not (ch == ">" and _nfkc(text[ce : ce + 1]) == "="):
                continue
            at_line_start = False
            if spaced:
                low = ch.lower()
                ch = low if len(low) == 1 else ch
            out.append(ch)
            starts.append(cs)
            ends.append(ce)
            gaps.append(0)
    consistent = "".join(parts) == _nfkc(text)
    return Normalized("".join(out), starts, ends, bytes(gaps), consistent)
