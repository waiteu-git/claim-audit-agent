"""引用照合の正規化と、原文オフセットの復元（設計 §5-1）。"""
import random
import unicodedata

import pytest

from app.quotes import normalize as N
from app.quotes.normalize import normalize
from app.textsafe import BLOCK_SEP as SEP


def flat(s: str) -> str:
    return normalize(s).text


def test_fullwidth_and_halfwidth_forms_fold_to_the_same_text():
    assert flat("ＡＢＣ１２３") == flat("ABC123") == "ABC123"
    assert flat("ﾃｽﾄ") == flat("テスト") == "テスト"


def test_halfwidth_voiced_kana_is_one_cluster_that_maps_back_whole():
    # 1文字ずつ NFKC をかけると ｶ+ﾞ がガにならない。クラスタで扱うので元の2文字ぶんに戻る
    n = normalize("あｶﾞい")
    assert n.text == "あガい"
    assert (n.starts[1], n.ends[1]) == (1, 3)
    assert (n.starts[2], n.ends[2]) == (3, 4)


def test_combining_voiced_mark_composes_with_its_base():
    n = normalize("がく")
    assert n.text == "がく"
    assert (n.starts[0], n.ends[0]) == (0, 2)


def test_compatibility_ideograph_maps_to_the_unified_one():
    assert flat("豈") == "豈"


def test_whitespace_of_every_kind_is_dropped():
    assert flat("提出 物\n説明\t文　です よ") == "提出物説明文ですよ"


def test_block_separator_is_not_part_of_the_output_but_leaves_a_gap_mark():
    # str.isspace() は U+001E を空白と判定する。出力に載せないのは正しいが、境界の位置は DocIndex が別に持つ
    assert SEP.isspace()
    n = normalize(f"A{SEP}B")
    assert n.text == "AB" and n.gap_after[0] == 1


@pytest.mark.parametrize("ch", ["​", "‍", "‮", "⁦", "﻿", "­", "\U000e0041", "️", "͏", "ㅤ"])
def test_invisible_characters_are_dropped(ch):
    assert flat(f"必{ch}須") == "必須"


def test_markdown_marks_are_dropped_but_angle_and_hash_only_at_line_start():
    assert flat("**必須**") == "必須"
    assert flat("`code`_x|y\\z") == "codexyz"
    assert flat("> 引用です") == "引用です"
    assert flat("## 見出し") == "見出し"
    assert flat("x>=5") == "x>=5"  # 比較演算子
    assert flat("C#言語") == "C#言語"  # 言語名の一部
    assert flat("行1\n> 行2") == "行1行2"  # 行頭の > は落ちる


def test_gap_marks_distinguish_spaced_ascii_words():
    assert normalize("no table").gap_after[1] == 1  # 'o' の後ろに空白
    assert normalize("notable").gap_after[1] == 0


def test_spaced_mode_keeps_word_breaks_and_lowercases_without_changing_length():
    n = normalize("Do  NOT\nSubmit", spaced=True)
    assert n.text == "do not submit"
    assert len(n.starts) == len(n.text)


def test_text_that_is_nothing_but_noise_normalizes_to_empty():
    assert flat(" ​‍\n**") == ""


def test_zalgo_run_is_bounded_and_consistent():
    n = normalize("e" + "́" * 20000 + "あ")
    assert n.consistent and n.text.endswith("あ")


def test_clusters_never_split_a_composition():
    assert N.clusters("が") == [(0, 1)]
    assert N.clusters("ｶﾞ") == [(0, 2)]
    assert N.clusters("éa") == [(0, 2), (2, 3)]
    assert N.clusters("각x") == [(0, 3), (3, 4)]  # ハングルの字母 L+V+T


_POOL = (
    list("abcA1 \n\t　あ漢字カ。")
    + ["か", "が", "ﾞ", "゙", "ｶ", "ｶﾞ", "ﾊﾟ", "e", "́", "̣", "̇", "̸", "=", "​", "️"]
    + ["ᄀ", "ᅡ", "ᆨ", "각", "㌔", "ﬁ", "①", "²", "Ａ", "１", "％", "…", SEP, "େ", "ା", "ီ", "ཱ", "ྀ", "ｱ", "ﾝ"]
)


def _reference(text: str) -> str:
    """vq.py と同じ規則（全体に NFKC → 空白・不可視・markdown 記号を除去）。"""
    return "".join(
        c
        for c in unicodedata.normalize("NFKC", text)
        if not (c.isspace() or N._is_ignorable(c) or c in N.ALWAYS_DROP)
    )


def test_normalization_equals_whole_string_nfkc_and_offsets_are_consistent():
    """クラスタごとの NFKC が、全体にかけた NFKC と一致する（vq.py と同じ結果）。位置も単調で、各文字の出所に含まれる。"""
    rnd = random.Random(20261002)
    for _ in range(4000):
        t = "".join(rnd.choice(_POOL) for _ in range(rnd.randint(1, 14)))
        n = normalize(t)
        assert n.consistent, ascii(t)
        assert n.text == _reference(t), ascii(t)
        prev = -1
        for k, ch in enumerate(n.text):
            s, e = n.starts[k], n.ends[k]
            assert prev <= s < e <= len(t)
            assert ch in unicodedata.normalize("NFKC", t[s:e])
            prev = s


def test_broken_clustering_is_detected_not_trusted(monkeypatch):
    monkeypatch.setattr(N, "_inert", lambda ch: True)  # 全部を別々のクラスタにすると か+゛ が合成されない
    assert normalize("が").consistent is False
