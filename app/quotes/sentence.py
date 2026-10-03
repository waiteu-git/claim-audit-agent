"""検証済みの区間を原文の1文へ広げる（snap_to_sentence。設計 §5-1 S-02）。

文末は 。．！？!? とブロック境界 U+001E。注入疑いで置換した区間（barriers）も境界として扱う
（置換された中身は信用できない文なので、文に取り込まず、読みにも行かない）。
英文のピリオド「.」は文末にしない（"3.5" や "e.g." で切れて、否定語の手前で文が終わるのを避ける。
その代わり英文は長い1文になりやすく、160字を超えれば推測へ降格する＝安全側）。

括弧（「」『』（）【】〔〕…）の中の句点は文末にしない。「「提出は必須です。」と誤解されがちですが…」の句点で切ると、
括弧の中の文だけが取り出され、外側の文が持つ打ち消し（誤解・旧版）が落ちる。括弧が閉じないまま続けば、文は
ブロック境界まで（最大 SCAN_LIMIT 字）延び、160字を超えれば推測へ降格する＝安全側。
"""
from array import array
from collections.abc import Sequence
from functools import lru_cache

from app.quotes.normalize import CELL_SEPARATORS
from app.textsafe import BLOCK_SEP

TERMINATORS = frozenset("。．！？!?")
# 文末記号の後ろに付いて、同じ文に属する閉じ括弧・引用符。
CLOSERS = frozenset("」』）)】〕］]｣”’\"'》〉")
# 括弧の深さを数える対象（対になる括弧だけ。' と " と ’ は同じ字が開きにも閉じにも、アポストロフィにも使われるので数えない）。
OPENERS = frozenset("「『（(【〔［[｢“《〈")
PAIR_CLOSERS = frozenset("」』）)】〕］]｣”》〉")
# 画面に出せる引用は160字まで。それより遠くまで探しても、結果は「長すぎる」にしかならない。
SCAN_LIMIT = 200
_URLISH = frozenset("=&%_/#.-+~:@")
# 文を切る境界: ブロック境界と、表のセル区切り（markdown の表は | でセルを分ける）。
_BOUNDARIES = frozenset({BLOCK_SEP}) | CELL_SEPARATORS

Barrier = tuple[int, int]


def is_terminator(text: str, i: int) -> bool:
    c = text[i]
    if c not in TERMINATORS:
        return False
    if c in "!?":
        # URL のクエリ（?x=1）で文を切らない
        nxt = text[i + 1] if i + 1 < len(text) else ""
        return not (nxt and nxt.isascii() and (nxt.isalnum() or nxt in _URLISH))
    if c == "．":
        # 全角のピリオドが小数点（３．５）として使われている場合
        prev = text[i - 1] if i > 0 else ""
        nxt = text[i + 1] if i + 1 < len(text) else ""
        return not (prev.isdigit() and nxt.isdigit())
    return True


_MAX_DEPTH = 60000  # array("H") に収まる深さ（開き括弧だけが延々と続く入力で OverflowError にしない）


@lru_cache(maxsize=32)
def _block_depths(text: str, b0: int) -> array:
    """b0 から始まるブロック（次のブロック境界・セル区切りまで）の各文字の直前の括弧の深さ。

    ブロックの先頭から数えるので、どの位置から snap しても同じ深さになる（最終再検証が、昇格時と同じ区間を再現できる）。
    閉じない括弧はブロックの終わりで打ち切る（次のブロックへ持ち越さない）。
    """
    out = array("H")
    d = 0
    for i in range(b0, len(text)):
        c = text[i]
        if c in _BOUNDARIES:
            break
        out.append(d)
        if c in OPENERS:
            d = min(d + 1, _MAX_DEPTH)
        elif c in PAIR_CLOSERS and d > 0:
            d -= 1
    return out


def _block_start(text: str, pos: int) -> int:
    return max((text.rfind(c, 0, pos) for c in _BOUNDARIES), default=-1) + 1


def snap_to_sentence(
    text: str, start: int, end: int, barriers: Sequence[Barrier] = (), *, scan_limit: int = SCAN_LIMIT
) -> tuple[int, int]:
    """[start, end) を含む1文の区間 (s, e) を返す。前後の空白は除く。s <= start, e >= end。"""
    if not 0 <= start < end <= len(text):
        raise ValueError("区間が原文の外です")
    lo = max(0, start - scan_limit)
    hi = min(len(text), end + scan_limit)
    origin = _block_start(text, start)
    depth = _block_depths(text, origin)

    def terminates(i: int) -> bool:
        """文末記号で、かつ括弧の外にある（括弧の中の句点では切らない）。"""
        k = i - origin
        return is_terminator(text, i) and (depth[k] == 0 if 0 <= k < len(depth) else True)

    s = lo
    i = start - 1
    while i >= lo:
        c = text[i]
        if c in _BOUNDARIES:
            s = i + 1
            break
        if terminates(i):
            s = i + 1
            while s < start and (text[s] in CLOSERS or text[s].isspace()):
                s += 1
            break
        i -= 1
    for bs, be in barriers:
        if be <= start:
            s = max(s, be)

    j = end - 1
    while j > start and (text[j] in CLOSERS or text[j].isspace()):
        j -= 1
    e = hi
    ended_by_terminator = False
    if terminates(j):
        e = end  # 引用そのものが文末記号で終わっている
        ended_by_terminator = True
    else:
        k = end
        while k < hi:
            if text[k] in _BOUNDARIES:
                e = k
                break
            if terminates(k):
                e = k + 1
                ended_by_terminator = True
                break
            k += 1
    if ended_by_terminator:
        while e < len(text) and e < hi and text[e] in CLOSERS:
            e += 1
    for bs, be in barriers:
        if bs >= end:
            e = min(e, bs)
    e = max(e, end)

    while s < start and text[s].isspace():
        s += 1
    while e > end and text[e - 1].isspace():
        e -= 1
    return s, e


def ends_with_terminator(text: str, s: int, e: int) -> bool:
    """区間 [s, e) が文末記号（と閉じ括弧）で終わっている。"""
    j = e - 1
    while j >= s and (text[j] in CLOSERS or text[j].isspace()):
        j -= 1
    return j >= s and is_terminator(text, j)


def block_follows(text: str, e: int) -> bool:
    """e の直後がブロック境界で、その先に本文のあるブロックが続く（文が箇条書き・本文の手前で終わっている）。"""
    n = len(text)
    i = e
    while i < n and text[i] != BLOCK_SEP and text[i].isspace():
        i += 1
    if i >= n or text[i] != BLOCK_SEP:
        return False
    while i < n and text[i].isspace():  # 空のブロック（連続した境界）と空白を越える
        i += 1
    return i < n


def previous_block(text: str, s: int) -> tuple[int, int] | None:
    """文の先頭 s がブロックの頭なら、その直前のブロックの区間 [b, e)。文がブロックの途中から始まる・文書の先頭なら None。"""
    i = s - 1
    while i >= 0 and text[i] != BLOCK_SEP and text[i].isspace():
        i -= 1
    if i < 0 or text[i] != BLOCK_SEP:
        return None
    end = i
    while end > 0 and text[end - 1].isspace():
        end -= 1
    if end <= 0:
        return None
    return text.rfind(BLOCK_SEP, 0, end) + 1, end


def next_sentence_head(
    text: str, e: int, barriers: Sequence[Barrier] = (), *, limit: int = 40
) -> tuple[int, int] | None:
    """文の直後の文の先頭 limit 字（空白を除いて数える）の区間。無ければ None（設計 §5-1 否定・例外語の走査範囲）。"""
    n = len(text)
    i = e
    while i < n:
        c = text[i]
        if c in _BOUNDARIES or c.isspace() or c in CLOSERS:
            i += 1
            continue
        hit = next((be for bs, be in barriers if bs <= i < be), None)
        if hit is not None:  # 置換区間は読まずに越える
            i = hit
            continue
        break
    if i >= n:
        return None
    j = i
    count = 0
    depth = 0
    barrier_starts = {bs for bs, _ in barriers}
    while j < n and count < limit:
        c = text[j]
        if c in _BOUNDARIES or j in barrier_starts:
            break
        if c in OPENERS:
            depth += 1
        elif c in PAIR_CLOSERS and depth > 0:
            depth -= 1
        if not c.isspace():
            count += 1
        j += 1
        if depth == 0 and is_terminator(text, j - 1):
            break
    return (i, j) if j > i else None
