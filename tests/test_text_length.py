"""text_length: 字数の数え方（全角/半角/空白/改行/絵文字）・上限の取り出し・不適合/適合/確認不能の境界。"""
import pytest

import app.contracts as C
from app.checks.text_length import (
    CharCounts,
    check_text_length,
    count_chars,
    extract_limit,
    grapheme_count,
    measure,
    utf16_len,
)
from app.textsafe import BLOCK_SEP
from tests.factories import make_doc, make_verified, seal

SUB = C.DocRole.SUBMISSION


# ---------------------------------------------------------------------------
# 数え方
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "with_ws", "no_ws"),
    [
        ("あいうえお", 5, 5),  # 全角
        ("abcde", 5, 5),  # 半角
        ("あaいbう", 5, 5),  # 混在
        ("あ い　う", 5, 3),  # 半角空白・全角空白（U+3000）は空白除去で消える
        ("あ\tい", 3, 2),  # タブ
        ("あ\nい", 3, 2),  # 改行
        ("あ\r\nい", 3, 2),  # CRLF は改行1つ（2文字に数えない）
        ("あ\rい", 3, 2),  # CR だけも改行1つ
        (f"あ{BLOCK_SEP}い", 3, 2),  # サニタイザのブロック境界は改行1つ
        (f"あ{BLOCK_SEP}{BLOCK_SEP}{BLOCK_SEP}い", 3, 2),  # 境界の連続（入れ子のブロック）も改行1つ
        (f"{BLOCK_SEP}\n  あい  \n{BLOCK_SEP}", 2, 2),  # 前後の空白・境界は数えない
        ("", 0, 0),
        ("   \n\n", 0, 0),
        ("あ い", 3, 2),  # NBSP も空白
    ],
)
def test_count_chars_whitespace_rules(text, with_ws, no_ws):
    c = count_chars(text)
    assert (c.chars_with_ws, c.chars_no_ws) == (with_ws, no_ws)


def test_count_chars_nfc_composes_combining_dakuten():
    """か＋結合濁点は NFC で「が」1字（PC の入力方式の違いで字数が変わらない）。"""
    assert count_chars("が").chars_with_ws == 1
    assert count_chars("が").chars_with_ws == 1


def test_emoji_is_one_code_point_but_two_utf16_units():
    c = count_chars("あ😀")
    assert (c.chars_with_ws, c.chars_no_ws) == (2, 2)
    assert c.units_min == 2  # 書記素
    assert c.units_max == 3  # UTF-16（JavaScript の length 相当）
    assert utf16_len("😀") == 2 and utf16_len("あ") == 1


@pytest.mark.parametrize(
    ("text", "graphemes", "code_points"),
    [
        ("👨‍👩‍👧", 1, 5),  # ZWJ 連結の家族
        ("🇯🇵", 1, 2),  # 国旗（地域指示子2つ）
        ("🇯🇵🇺🇸", 2, 4),
        ("👍🏽", 1, 2),  # 肌の色の修飾
        ("❤️", 1, 2),  # 異体字セレクタ
        ("ｶﾞ", 1, 2),  # 半角カナ＋濁点
        ("é", 1, 2),  # 結合アクセント（NFC 前の生の文字列。count_chars は NFC するので別）
        ("あいう", 3, 3),
        ("", 0, 0),
    ],
)
def test_grapheme_count_groups_what_a_person_counts_as_one(text, graphemes, code_points):
    assert grapheme_count(text) == graphemes
    assert len(text) == code_points


def test_count_chars_reports_min_and_max_conventions():
    c = count_chars("あ い\n😀")
    assert c.chars_no_ws < c.chars_with_ws
    assert c.units_min <= c.chars_no_ws <= c.chars_with_ws <= c.units_max


# ---------------------------------------------------------------------------
# 判定の境界: 両方超過だけ不適合・両方以内だけ適合・割れたら確認不能
# ---------------------------------------------------------------------------
def counts(text: str) -> CharCounts:
    return count_chars(text)


def test_exactly_at_the_limit_is_within_and_one_over_is_over():
    at = counts("あ" * 800)
    assert measure(at, 800)[0] is C.ObsCode.WITHIN_LIMIT
    over = counts("あ" * 801)
    assert measure(over, 800)[0] is C.ObsCode.OVER_LIMIT
    code, outcome, strong = measure(over, 800)
    assert (outcome, strong) == (C.ObsOutcome.FAIL, True)
    assert measure(at, 800)[1:] == (C.ObsOutcome.PASS, True)


def test_with_whitespace_over_but_without_whitespace_within_is_undecidable():
    text = "あ" * 395 + " " * 20 + "あ" * 395  # 空白込み810字・空白なし790字。上限800（前後の空白は数えないので途中に置く）
    code, outcome, strong = measure(counts(text), 800)
    assert (code, outcome, strong) == (C.ObsCode.LIMIT_UNDECIDABLE, C.ObsOutcome.INCONCLUSIVE, False)


def test_over_even_without_whitespace_is_a_fail():
    text = "あ" * 405 + " " * 20 + "あ" * 405
    assert measure(counts(text), 800)[0] is C.ObsCode.OVER_LIMIT


def test_both_within_with_whitespace_is_a_pass():
    assert measure(counts("あ" * 350 + " " * 100 + "あ" * 350), 800)[0] is C.ObsCode.WITHIN_LIMIT


def test_newlines_count_in_the_with_whitespace_measure_only():
    text = "\n".join(["あ" * 99] * 10)  # 990字＋改行9 = 999字（空白込み）・990字（なし）
    c = counts(text)
    assert (c.chars_with_ws, c.chars_no_ws) == (999, 990)
    assert measure(c, 1000)[0] is C.ObsCode.WITHIN_LIMIT
    assert measure(c, 995)[0] is C.ObsCode.LIMIT_UNDECIDABLE  # 改行込みだと超える
    assert measure(c, 980)[0] is C.ObsCode.OVER_LIMIT


def test_emoji_at_the_boundary_is_undecidable_not_a_guess():
    """上限3字・「あい😀」: コードポイントでは3字で収まるが、JavaScript の length では4で超える。数え方が割れるので決めない。"""
    c = counts("あい😀")
    assert measure(c, 3)[0] is C.ObsCode.LIMIT_UNDECIDABLE
    assert measure(c, 4)[0] is C.ObsCode.WITHIN_LIMIT  # どの数え方でも収まる
    assert measure(counts("あい😀😀"), 3)[0] is C.ObsCode.OVER_LIMIT  # 最小の数え方（書記素4）でも超える


def test_zwj_emoji_cannot_make_a_false_fail():
    """家族の絵文字（ZWJ 連結）は見た目1字。コードポイントでは5だが、不適合の根拠にしない。"""
    c = counts("👨‍👩‍👧")
    assert measure(c, 1)[0] is not C.ObsCode.OVER_LIMIT


# ---------------------------------------------------------------------------
# 要項の引用から上限を取り出す
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("quote", "limit", "exclusive"),
    [
        ("提出物の説明は800字以内とする。", 800, False),
        ("説明文は800文字以下で記載すること。", 800, False),
        ("説明文は１，０００文字以内", 1000, False),  # 全角数字・全角カンマ
        ("説明は 1,000 字以内", 1000, False),
        ("800字までとする。", 800, False),
        ("800字未満であること。", 799, True),
        ("説明は400字以上800字以内とする。", 800, False),  # 下限があっても上限を採る
        ("説明は400〜800字とする。", 800, False),  # 範囲は後ろの数値が上限
        ("説明は400から800字とする。", 800, False),
        ("文字数の上限は800字です。", 800, False),
        ("最大800字", 800, False),
        ("上限1000文字", 1000, False),
        ("文字数は800以内", 800, False),  # 単位が数値の後ろに無い形
        ("説明は800字以内（空白を含む）。", 800, False),
        ("800字（空白を含む）以内", 800, False),
        ("The description must be within 800 characters.", 800, False),
        ("Up to 800 chars are allowed.", 800, False),
        ("800 characters or less", 800, False),
        ("Fewer than 800 characters", 799, True),
        ("全角800字以内", 800, False),
    ],
)
def test_extract_limit_reads_the_number_in_the_quote(quote, limit, exclusive):
    spec = extract_limit(quote)
    assert (spec.limit, spec.exclusive) == (limit, exclusive)
    assert spec.reason == ""


@pytest.mark.parametrize(
    ("quote", "reason"),
    [
        ("提出物の説明を記載すること。", "no_upper_limit"),  # 数値が無い
        ("説明は500字。", "no_upper_limit"),  # 数値はあるが上限と言っていない
        ("説明は200字以上で記載すること。", "lower_bound_only"),
        ("8文字以上のパスワード", "lower_bound_only"),
        ("説明は800字程度とする。", "approximate_only"),  # 目安は上限ではない
        ("タイトルは50字以内、説明は800字以内", "ambiguous_limit"),  # どちらが対象か決められない
        ("全角800字（半角1600字）以内", "width_dependent"),  # 全角・半角で重みが違う数え方
        ("動画は3分以内", "no_upper_limit"),  # 字数でない単位
        ("締切は10月15日です。", "no_upper_limit"),
        ("", "no_upper_limit"),
        ("説明は0字以内", "no_upper_limit"),  # 0 は上限として扱わない
    ],
)
def test_extract_limit_refuses_to_guess(quote, reason):
    spec = extract_limit(quote)
    assert spec.limit is None and spec.reason == reason


def test_extract_limit_uses_only_a_number_that_exists_in_the_quote():
    """検証済み引用に無い数値（設計書の 800 など）は、どこからも出てこない。"""
    assert extract_limit("説明を記載すること。").limit is None
    assert extract_limit("上限は別途お知らせします。").limit is None


# ---------------------------------------------------------------------------
# チェッカー（要件の検証済み引用 × 提出物の文書 → 観測）
# ---------------------------------------------------------------------------
def spec_req(needle: str = "説明は800字以内とする。", **kw):
    spec = make_doc("D1", f"応募要項{BLOCK_SEP}{needle}{BLOCK_SEP}締切は10月15日である。")
    return make_verified("R1", doc=spec, needle=needle, check_class=C.CheckClass.LENGTH_LIMIT, **kw)


def submission(text: str, doc_id: str = "D3", **kw):
    return make_doc(doc_id, text, role=SUB, label="架空の提出物", url="https://svc.example.invalid/fx/defect/submission/", **kw)


def test_demo_defect_d1_is_a_strong_fail_by_both_measures():
    """デモ② D1: 公開説明文が1,130字で上限800字超（両方式で超過・OBS強）。"""
    body = ("あ" * 100 + "。\n") * 11 + "い" * 19  # 1,130字前後
    doc = submission(body)
    obs = check_text_length(spec_req(), doc, "O1")
    assert obs.tool is C.ToolName.RUN_CHECK and obs.checker is C.Checker.TEXT_LENGTH
    assert (obs.req_id, obs.doc_id, obs.obs_id) == ("R1", "D3", "O1")
    assert (obs.code, obs.outcome, obs.strong) == (C.ObsCode.OVER_LIMIT, C.ObsOutcome.FAIL, True)
    f = obs.facts
    assert f["limit"] == 800 and f["over_with_ws"] is True and f["over_no_ws"] is True
    assert f["chars_with_ws"] > f["chars_no_ws"] > 800


def test_within_limit_is_a_strong_pass():
    obs = check_text_length(spec_req(), submission("あ" * 799), "O2")
    assert (obs.code, obs.outcome, obs.strong) == (C.ObsCode.WITHIN_LIMIT, C.ObsOutcome.PASS, True)
    assert obs.facts["over_with_ws"] is False and obs.facts["over_no_ws"] is False


def test_only_one_measure_over_is_inconclusive():
    obs = check_text_length(spec_req(), submission("あ" * 395 + " " * 20 + "あ" * 395), "O3")
    assert (obs.code, obs.outcome, obs.strong) == (C.ObsCode.LIMIT_UNDECIDABLE, C.ObsOutcome.INCONCLUSIVE, False)
    assert obs.facts["over_with_ws"] is True and obs.facts["over_no_ws"] is False


def test_strict_upper_bound_uses_n_minus_1():
    req = spec_req("説明は800字未満とする。")
    assert check_text_length(req, submission("あ" * 800), "O1").code is C.ObsCode.OVER_LIMIT
    obs = check_text_length(req, submission("あ" * 799), "O1")
    assert obs.code is C.ObsCode.WITHIN_LIMIT and obs.facts["limit"] == 799 and obs.facts["exclusive"] is True


def test_no_number_in_the_quote_is_no_parameter_not_a_guess():
    obs = check_text_length(spec_req("説明を記載すること。"), submission("あ" * 5000), "O1")
    assert (obs.code, obs.outcome, obs.strong) == (C.ObsCode.NO_PARAMETER, C.ObsOutcome.INCONCLUSIVE, False)
    assert obs.facts["why"] == "no_upper_limit"


def test_ambiguous_limits_are_no_parameter_with_the_candidate_count():
    obs = check_text_length(spec_req("タイトルは50字以内、説明は800字以内とする。"), submission("あ" * 900), "O1")
    assert obs.code is C.ObsCode.NO_PARAMETER and obs.facts == {"why": "ambiguous_limit", "candidates": 2}


def test_speculative_requirement_without_a_quote_has_no_parameter():
    req = C.VerifiedRequirement(
        seal=seal(), req_id="R1", kind=C.Kind.SPECULATIVE, declared_kind=C.Kind.REQUIRED,
        check_class=C.CheckClass.LENGTH_LIMIT, span=None, demotion=C.DemotionReason.QUOTE_UNVERIFIED, gist="説明は500字以内のはず",
    )  # fmt: skip
    obs = check_text_length(req, submission("あ" * 900), "O1")
    assert obs.code is C.ObsCode.NO_PARAMETER and obs.facts == {"why": "no_quote"}


def test_facts_never_carry_page_text():
    secret = "ひみつの本文ABC"
    obs = check_text_length(spec_req(), submission(secret * 200), "O1")
    for v in obs.facts.values():
        assert not (isinstance(v, str) and ("ひみつ" in v or "ABC" in v))
    assert "ひみつ" not in obs.model_dump_json()


def test_truncated_document_is_recorded_in_the_facts():
    obs = check_text_length(spec_req(), submission("あ" * 900, truncated=True), "O1")
    assert obs.facts["truncated"] is True and obs.code is C.ObsCode.OVER_LIMIT  # 打切りでも超過は超過


def test_block_separators_added_by_the_sanitizer_do_not_inflate_the_no_whitespace_count():
    text = BLOCK_SEP.join(["あ" * 100] * 8)  # 800字＋境界7
    obs = check_text_length(spec_req(), submission(text), "O1")
    assert obs.facts["chars_no_ws"] == 800 and obs.facts["chars_with_ws"] == 807
    assert obs.code is C.ObsCode.LIMIT_UNDECIDABLE  # 800字ぴったり。改行込みでは超える
