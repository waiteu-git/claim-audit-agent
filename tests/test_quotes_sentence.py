"""1文への拡張（snap_to_sentence）と、直後の文の先頭の取り出し（設計 §5-1 S-02）。"""
import pytest

from app.quotes.sentence import (
    SCAN_LIMIT,
    block_follows,
    is_terminator,
    next_sentence_head,
    previous_block,
    snap_to_sentence,
)
from app.textsafe import BLOCK_SEP as SEP


def snap(text: str, needle: str, barriers=()):
    a = text.index(needle)
    s, e = snap_to_sentence(text, a, a + len(needle), barriers)
    return text[s:e]


def test_expands_to_the_surrounding_sentence_and_trims_spaces():
    t = "前の文です。  提出は必須とする。次の文です。"
    assert snap(t, "必須") == "提出は必須とする。"


def test_sentence_ends_at_the_terminator_inclusive():
    t = "前の文です。提出物は動画を含めること。次の文です。"
    assert snap(t, "動画を含め") == "提出物は動画を含めること。"


def test_block_separator_is_a_hard_boundary_on_both_sides():
    t = f"見出し{SEP}提出物は動画を含めること{SEP}次のブロック。"
    assert snap(t, "動画") == "提出物は動画を含めること"


def test_quote_that_already_ends_with_the_terminator_keeps_that_end():
    t = "提出物は動画を含めること。次の文です。"
    assert snap(t, "動画を含めること。") == "提出物は動画を含めること。"


def test_closing_brackets_after_the_terminator_belong_to_the_sentence():
    t = "前の文です。提出物は動画を含めること。」次の文です。"  # 開いていない閉じ括弧（文末記号の後ろに付く）
    assert snap(t, "動画") == "提出物は動画を含めること。」"
    # 次の文の頭に閉じ括弧が残らない
    t2 = "A文です。」B文です。"
    assert not snap(t2, "B文").startswith("」")


def test_a_terminator_inside_brackets_does_not_end_the_sentence():
    # 敵対レビュー W5: 括弧の中の句点で切ると、括弧の中の文だけが取り出され、外側の「と誤解されがち」が落ちる。
    # 以前は「「…こと。」」で切っていた（閉じ括弧を取り込む設計）。外側の文末まで延ばす
    t = "「提出物は動画を含めること。」と定める。次です。"
    assert snap(t, "動画") == "「提出物は動画を含めること。」と定める。"
    t2 = "前です。（注：動画を含めること。ただし例外あり。）提出は必須とする。次です。"
    assert snap(t2, "動画") == "（注：動画を含めること。ただし例外あり。）提出は必須とする。"
    assert snap(t2, "次です") == "次です。"


def test_an_unclosed_bracket_does_not_carry_over_to_the_next_block():
    t = f"（注：動画を含めること。{SEP}提出は必須とする。{SEP}次です。"
    assert snap(t, "必須") == "提出は必須とする。"
    # 閉じない括弧の中は、ブロックの終わりまでが1文（句点では切れない）
    assert snap(t, "動画") == "（注：動画を含めること。"


def test_next_sentence_head_does_not_stop_at_a_terminator_inside_brackets():
    t = "本文です。「ただし。例外」を除く。さらに続く。"
    s, f = next_sentence_head(t, t.index("。") + 1)
    assert t[s:f] == "「ただし。例外」を除く。"


def test_previous_block_and_block_follows():
    t = f"【任意提出物】{SEP}デモ動画を提出してください。{SEP}{SEP}次の項目{SEP}末尾"
    s = t.index("デモ")
    assert previous_block(t, s) == (0, len("【任意提出物】"))
    assert previous_block(t, 0) is None
    assert previous_block("前の文。提出は必須。", 4) is None  # 文がブロックの途中から始まる
    e = t.index("。") + 1
    assert block_follows(t, e) and not block_follows(t, len(t))
    assert block_follows(t, t.index("次の項目") + 4)
    assert not block_follows("提出は必須とする。", 9)


@pytest.mark.parametrize("text,i,expected", [
    ("終わり。", 3, True),
    ("終わり！", 3, True),
    ("終わり？", 3, True),
    ("end!", 3, True),
    ("end? next", 3, True),
    ("end.", 3, False),  # 英文のピリオドは文末にしない
    ("http://x.example.invalid/a?b=1", 26, False),  # URL のクエリ
    ("３．５分", 1, False),  # 全角ピリオドの小数点
    ("終わり．次", 3, True),  # 全角ピリオドの文末
])
def test_terminator_rules(text, i, expected):
    assert is_terminator(text, i) is expected


def test_injection_placeholder_range_is_a_boundary():
    t = "前の文〔注入疑い〕提出は必須とする。"
    a = t.index("〔")
    barrier = [(a, a + len("〔注入疑い〕"))]
    assert snap(t, "必須", barrier) == "提出は必須とする。"
    t2 = "提出は必須とする〔注入疑い〕続きの文。"
    b = t2.index("〔")
    assert snap(t2, "必須", [(b, b + 6)]) == "提出は必須とする"


def test_scan_is_bounded_so_a_terminator_free_text_yields_an_oversize_span():
    t = "あ" * 1000 + "必須" + "い" * 1000
    a = t.index("必須")
    s, e = snap_to_sentence(t, a, a + 2)
    assert e - s > 160 and e - s <= 2 * SCAN_LIMIT + 2


def test_span_outside_text_is_rejected():
    with pytest.raises(ValueError):
        snap_to_sentence("abc", 2, 5)


def test_next_sentence_head_skips_boundaries_and_takes_forty_characters():
    t = "本文です。" + SEP + "ただし、" + "あ" * 80 + "。"
    e = t.index("。") + 1
    s, f = next_sentence_head(t, e)
    assert t[s:f].startswith("ただし") and len([c for c in t[s:f] if not c.isspace()]) == 40


def test_next_sentence_head_stops_at_its_own_terminator_and_at_none():
    t = "本文です。除く場合。さらに続く文。"
    s, f = next_sentence_head(t, t.index("。") + 1)
    assert t[s:f] == "除く場合。"
    assert next_sentence_head("末尾です。", 5) is None


def test_next_sentence_head_steps_over_a_replaced_injection_range():
    t = "本文です。〔注入疑い〕ただし例外あり。"
    a = t.index("〔")
    s, f = next_sentence_head(t, t.index("。") + 1, [(a, a + 6)])
    assert t[s:f] == "ただし例外あり。"
