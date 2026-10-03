"""引用検証器への敵対レビュー（攻撃者の目で破りに行った記録）。

どの攻撃も「検証済みなのに意味が逆」「条件が落ちる」「最終再検証をすり抜ける」の形で、
修正前は『逐語一致・昇格』のまま通っていたもの。各テストは再現テスト（修正前は赤）で、
対になる陽性対照（正しい要件が降格されない）も置いてある＝「何でも降格する」実装で緑にならない。
文章はすべて合成した架空のもの。

攻撃の種類（W番号は tests の節と対応）:
  W1  否定された義務語（必須としません・義務はありません・禁止していません・No ... is required）を、文全体を引用して通す
  W2  必須と禁止の取り違え（してはならない文を「必須」で通す）
  W3  任意・依頼と申告して、必須・禁止の文を弱める
  W4  疑問文（FAQ の「Q. …必須ですか？」）を断定として通す
  W5  断定でない文（仮定・予定・推量・誤解の紹介・旧規約・定義）を通す
  W6  引用の外の条件（場合・とき・if/when）が落ちる
  W7  例外・否定の語彙の穴（もっとも・例外・無し・aside from）
  W8  箇条書きの手前切り（見出しの文だけを要件にする）と、直前の見出しが任意・推奨
  W9  同じ引用が複数の文書にあり、例外が付く方でなく先頭の文書の文が採られる
  W10 最終再検証のすり抜け（表のセルをまたぐ区間・検証器が出していない昇格の書き換え）
"""
import pytest

from app.contracts import (
    Chip,
    DemotionReason as D,
    Kind,
    VerifiedRequirement,
    VerifiedSpan,
)
from app.quotes import QuoteChecker, ReverifyFailure as F
from app.quotes import checker as checker_mod
from app.textsafe import BLOCK_SEP as SEP
from tests.quotes_util import checker, doc, raw

REQ, PRO, OPT, REQST, SPEC_ = Kind.REQUIRED, Kind.PROHIBITED, Kind.OPTIONAL, Kind.REQUEST, Kind.SPECULATIVE


def run(blocks, quote, kind=REQ, *more_docs) -> VerifiedRequirement:
    chk = checker(doc(*blocks), *more_docs)
    out = chk.resolve(raw(quote, kind), "R1")
    assert out.requirement is not None
    return out.requirement


def sent(s, kind=REQ) -> VerifiedRequirement:
    """1文だけの文書で、その文全体（末尾の句点を除く）を引用する。"""
    return run([s], s.rstrip("。.?？!！"), kind)


def assert_not_assertive(r: VerifiedRequirement, why: str = "") -> None:
    """断定の kind（必須・禁止・任意・依頼）のまま昇格していない。

    引用が逐語一致した（span がある）上で、意味の検査で降格したことまで確かめる。引用が棄却されて「引用なしの推測」に
    落ちただけ（テストの引用の作り間違い）では、攻撃を防いだことにならないので通さない。"""
    assert r.span is not None, f"引用が検証に通っていない（攻撃になっていない）: {r.demotion} {why}"
    assert r.demotion is not None, f"昇格してしまった: {r.kind.value} {r.span.original_span!r} {why}"
    assert r.demotion is not D.QUOTE_UNVERIFIED and r.kind in (SPEC_, OPT), r


def assert_promoted(r: VerifiedRequirement, kind: Kind) -> None:
    assert r.demotion is None and r.kind is kind, (r.kind, r.demotion, r.span.original_span if r.span else None)


# =====================================================================================================
# W1 否定された義務語を、文全体を引用して通す。否定語が引用の中にあるので「引用の外の否定語」の検査は働かない。
# =====================================================================================================
OBLIGATION_HEADS = [
    ("動画の提出が必須", REQ),
    ("動画の提出が義務", REQ),
    ("動画の提出が必要", REQ),
    ("他者の著作物の使用が禁止", PRO),
    ("他者の著作物の使用が不可", PRO),
]
NEGATING_TAILS = [
    "ではありません",
    "ではない",
    "とはいえません",
    "とはいえない",
    "とは言えない",
    "としません",
    "とはしていません",
    "とされていません",
    "とはされていません",
    "とは限りません",
    "とは言い切れません",
    "ではございません",
    "じゃない",
    "ではなくなりました",
    "でなくなった",
    "とはなっておりません",
    "とは考えていません",
    "には該当しません",
    "とされる項目のひとつではありません",  # 否定が義務語から離れている（12字を超える）
    "とされている項目の中には含まれておりません",
]
POSITIVE_TAILS = ["です", "とする", "とします", "である", "となります", "とされています"]


@pytest.mark.parametrize("tail", NEGATING_TAILS)
@pytest.mark.parametrize("head,kind", OBLIGATION_HEADS)
def test_w1_a_whole_sentence_that_negates_its_obligation_word_is_never_promoted(head, kind, tail):
    # 「必須としません」のように、否定が義務語の直後でない言い方。修正前は「必須」のまま昇格していた
    assert_not_assertive(sent(head + tail + "。", kind), head + tail)


@pytest.mark.parametrize("tail", POSITIVE_TAILS)
@pytest.mark.parametrize("head,kind", OBLIGATION_HEADS)
def test_w1_control_the_same_heads_with_an_affirmative_tail_are_promoted(head, kind, tail):
    # 否定の格子と同じ頭に、肯定の末尾を付けたもの。「何でも降格する」実装では緑にならない
    assert_promoted(sent(head + tail + "。", kind), kind)


@pytest.mark.parametrize(
    "sentence,kind",
    [
        ("動画を提出する義務はありません。", REQ),
        ("応募者は動画を提出する義務を負いません。", REQ),
        ("動画を提出する必要があるとは限りません。", REQ),
        ("動画を提出しなくても失格にはなりません。", REQ),
        ("動画を提出しない場合でも失格とはしません。", PRO),
        ("当社は他者の著作物の使用を禁止していません。", PRO),
        ("主催者は他者の著作物の使用を禁止しない。", PRO),
        ("他者の著作物の使用を禁止するものではありません。", PRO),
        ("他者の著作物の使用は禁じられておりません。", PRO),
        ("No demo video is required.", REQ),
        ("A demo video is no longer required.", REQ),
        ("A demo video is not necessarily required.", REQ),
        ("Using third-party libraries is no longer prohibited.", PRO),
        ("Nobody is required to submit a demo video.", REQ),
        ("応募にあたり動画の提出は非必須です。", REQ),
        ("応募にあたり動画の提出は不必須です。", REQ),
    ],
)
def test_w1_other_phrasings_of_a_negated_obligation(sentence, kind):
    assert_not_assertive(sent(sentence, kind))


@pytest.mark.parametrize(
    "quote",
    [
        "動画の提出は必須ではありませんが、字幕の提出は必須です",  # 文全体
        "字幕の提出は必須です",  # 肯定の節だけ
        "動画の提出は必須ではありません",  # 否定の節だけ
    ],
)
def test_w1_a_sentence_that_mixes_a_negated_and_an_affirmed_obligation_is_not_promoted_whichever_clause_is_quoted(quote):
    # 否定の節を引用しても、肯定の節の「必須」で文の kind が決まってしまう（意味が逆）。どの節を引用しても確定させない
    assert_not_assertive(run(["動画の提出は必須ではありませんが、字幕の提出は必須です。"], quote, REQ))


def test_w1_control_a_negation_that_belongs_to_another_word_in_the_same_clause_is_not_mixed():
    assert_promoted(sent("必須項目を入力しない場合は失格とする。", REQ), REQ)
    assert_promoted(sent("動画は必須とし、字幕はつけること。", REQ), REQ)


@pytest.mark.parametrize(
    "sentence,kind",
    [
        ("動画の提出は必須とする。", REQ),
        ("動画の提出が必須です。", REQ),
        ("必須項目を入力しなければ送信できません。", REQ),
        ("必須項目を入力しなければ先へ進めません。", REQ),  # 「なければ」の後の否定は、要求の言い方（否定の範囲に入れない）
        ("応募者は必ず日本語で記載しなければならない。", REQ),
        ("必須項目を空欄にしてはならない。", PRO),
        ("動画を提出しない場合は失格とする。", REQ),
        ("提出物にはデモ動画を含めること。", REQ),
        ("他者の著作物を使用してはならない。", PRO),
        ("応募者は他者の著作物を含めないこと。", PRO),
        ("未成年者は応募できません。", PRO),
        ("規約に違反した場合は失格とします。", PRO),
        ("A demo video is required.", REQ),
        ("Teams must not use copyrighted music.", PRO),
        ("Entries must be submitted no later than October 15.", REQ),
    ],
)
def test_w1_control_ordinary_obligations_are_still_promoted(sentence, kind):
    assert_promoted(sent(sentence, kind), kind)


# =====================================================================================================
# W2 必須と禁止の取り違え。Kind は必須と禁止を別に持ち、下流（判定表）の向きが変わる。
# 判定は明示の語だけ（禁止・してはならない／必須・必ず・しなければならない）。「できません」「不可」「〜しないこと」は
# 禁止の形で要求を言う（「ローカルのみは不可」「権利を侵害しないこと」）。人が必須と付けた文にも多いので向きを決めない。
# =====================================================================================================
@pytest.mark.parametrize(
    "sentence,declared",
    [
        ("応募者は、他者の著作物を無断で使用してはならない。", REQ),
        ("他者の著作物の使用は禁止します。", REQ),
        ("Teams must not use copyrighted music.", REQ),
        ("説明文は必ず日本語で記載しなければならない。", PRO),
        ("動画の提出は必須とする。", PRO),
        ("Teams must submit a demo video.", PRO),
    ],
)
def test_w2_a_prohibition_declared_as_required_or_the_reverse_is_not_promoted(sentence, declared):
    assert_not_assertive(sent(sentence, declared))


@pytest.mark.parametrize(
    "sentence",
    [
        "18歳以上でなければ応募できません。",
        "提出フォームに入力しないと応募は受け付けられず、失格となります。",
        "他者の著作物を使用しないこと。また、必ず出典を明記すること。",
        "必ず日本語で記載し、他者の著作物を使用してはならない。",
        "ローカル環境のみでの動作は不可です。",
        "提出者は第三者の権利を侵害しないこと。",
        "第三者の権利を侵害しないものとします。",
    ],
)
@pytest.mark.parametrize("declared", [REQ, PRO])
def test_w2_control_sentences_that_carry_both_directions_or_an_ambiguous_form_keep_either_kind(sentence, declared):
    assert_promoted(sent(sentence, declared), declared)


def test_w2_control_a_plain_requirement_declared_required_is_promoted():
    assert_promoted(sent("応募者は日本国内に居住していなければならない。", REQ), REQ)


# =====================================================================================================
# W3 任意・依頼と申告して、必須・禁止の文を弱める（違反を見逃す向きの反転）。
# =====================================================================================================
@pytest.mark.parametrize("declared", [OPT, REQST])
@pytest.mark.parametrize(
    "sentence",
    [
        "動画の提出は必須です。",
        "他者の著作物の使用は禁止します。",
        "未成年者は応募できません。",
        "応募者は必ず日本語で記載しなければならない。",
        "A demo video is required.",
    ],
)
def test_w3_a_mandatory_sentence_declared_optional_or_request_is_not_promoted(sentence, declared):
    assert_not_assertive(sent(sentence, declared))


@pytest.mark.parametrize(
    "sentence,declared",
    [
        ("動画の提出は任意です。", OPT),
        ("動画の提出は必須ではなく任意です。", OPT),
        ("提出物の公開をお願いします。", REQST),
        ("提出物の公開は推奨ですが、必須ではありません。", REQST),
        ("Teams are encouraged to submit a demo video.", REQST),
    ],
)
def test_w3_control_weak_sentences_declared_weak_are_still_promoted(sentence, declared):
    assert_promoted(sent(sentence, declared), declared)


# =====================================================================================================
# W4 疑問文。FAQ の質問文は義務語を含むが、何も主張していない（答えは「いいえ」かもしれない）。
# =====================================================================================================
@pytest.mark.parametrize(
    "blocks,quote",
    [
        (["Q. 動画の提出は必須ですか？", "A. いいえ、任意です。"], "動画の提出は必須ですか"),
        (["Q. 動画の提出は必須ですか", "A. いいえ。任意です。"], "動画の提出は必須ですか"),
        (["動画の提出は必須ですか。"], "動画の提出は必須ですか"),
        (["動画の提出は必須でしょうか。"], "動画の提出は必須でしょうか"),
        (["動画の提出は必須ですか？はい、必須です。"], "動画の提出は必須ですか"),
        (["Q. Is a demo video required?", "A. No, it is optional."], "Is a demo video required"),
        (["Q1. 他者の著作物を使用してもよいですか", "A. いいえ、使用できません。"], "他者の著作物を使用してもよいですか"),
        (["Q. 応募には動画の提出が必要ですか", "A. 任意です。"], "応募には動画の提出が必要ですか"),
    ],
)
def test_w4_a_question_is_not_a_requirement(blocks, quote):
    assert_not_assertive(run(blocks, quote, REQ))


def test_w4_control_the_answer_of_a_faq_is_promoted_and_a_statement_with_ka_inside_is_not_a_question():
    assert_promoted(run(["Q. 動画の提出は必須ですか？", "A. はい、動画の提出は必須です。"], "はい、動画の提出は必須です"), REQ)
    # 「か」を含むだけで疑問ではない
    assert_promoted(run(["動画の提出または画像の提出のいずれかが必須です。"], "動画の提出または画像の提出のいずれかが必須です"), REQ)
    assert_promoted(run(["応募者は動画か画像のどちらかを必ず提出しなければならない。"], "応募者は動画か画像のどちらかを必ず提出しなければならない", REQ), REQ)


# =====================================================================================================
# W5 断定でない文: 仮定・予定・推量・「〜と誤解されがち」・旧規約・定義。
# =====================================================================================================
@pytest.mark.parametrize(
    "sentence",
    [
        "「動画の提出は必須です。」と誤解されがちですが、実際は任意です。",
        "「動画の提出は必須です。」という記載は旧版のものです。",
        "仮に動画の提出が必須だとしても、本件は対象外です。",
        "動画の提出は今後必須とする予定です。",
        "動画の提出は必須でしょう。",
        "動画の提出が必須かどうかは別途お知らせします。",
        "必須とは、必ず提出しなければならないことを指す。",
        "以前は動画の提出が必須でした。",
        "動画の提出は必須としていたが、現在は廃止した。",
        "動画の提出は必須になるかもしれません。",
        "動画の提出を必須とする可能性があります。",
        "動画の提出を必須とすることを検討しています。",
        "（例）動画の提出は必須です。",
        '"A video is required" is a common misconception.',
        "A demo video may be required in the future.",
    ],
)
def test_w5_a_sentence_that_does_not_assert_is_not_promoted(sentence):
    # 文全体を引用しても、断定でないものは必須として確定させない（引用の外の語が無いので (A) は働かない）
    quote = sentence.rstrip("。.")
    assert_not_assertive(run([sentence], quote, REQ))


def test_w5_a_fragment_inside_quoted_speech_is_not_asserted_either():
    # 引用の外に「誤解」「記載」があるが、語彙に無い言い方でも、「」の中の文を取り出すと断定になる
    r = run(["「動画の提出は必須です。」と誤解されがちですが、実際は任意です。"], "動画の提出は必須です", REQ)
    assert_not_assertive(r)
    # 「」の外側の文が断定していれば、その文は通る
    assert_promoted(run(["「提出物」とは、動画と説明文の両方を指し、提出は必須です。"], "提出は必須です", REQ), REQ)


# =====================================================================================================
# W6 引用の外の条件が落ちる（引用が文の途中から始まる）。条件が引用の内側にあれば、見えているので降格しない。
# =====================================================================================================
@pytest.mark.parametrize(
    "sentence,quote",
    [
        ("海外在住の場合は、動画の提出が必須です。", "動画の提出が必須です"),
        ("審査員が必要と判断したときは、追加資料の提出が必須です。", "追加資料の提出が必須です"),
        ("チームで応募する際は、代表者の氏名の記載が必須です。", "代表者の氏名の記載が必須です"),
        ("海外在住の方は、動画の提出が必須です。", "動画の提出が必須です"),
        ("動画に音声を含めるなら、字幕の追加が必須です。", "字幕の追加が必須です"),
        ("A demo video is required if the app uses a camera.", "A demo video is required"),
        ("When the team is a company, a demo video is required.", "a demo video is required"),
        ("A demo video is required for every team, aside from student teams.", "A demo video is required for every team"),
    ],
)
def test_w6_a_condition_outside_the_quote_demotes(sentence, quote):
    r = run([sentence], quote, REQ)
    assert r.demotion is D.NEGATION_OR_EXCEPTION and Chip.NEGATION_OR_EXCEPTION in r.chips
    assert r.span is not None and r.span.original_span.rstrip(".。") == sentence.rstrip(".。")  # 条件ごと表示される


@pytest.mark.parametrize("heading", ["海外在住の方", "法人向け", "チームで参加する場合", "学生限定", "【海外在住の方へ】"])
def test_w6_a_heading_that_narrows_the_audience_demotes_the_sentence_below_it(heading):
    # 条件は見出しにあり、文には無い。見出しを見ないと、条件付きの要件が無条件の「必須」になる
    assert_not_assertive(run([heading, "動画の提出が必須です。"], "動画の提出が必須です", REQ))


def test_w6_control_an_ordinary_heading_does_not_demote():
    for heading in ("提出物", "応募資格", "【必須提出物】", "審査について"):
        assert_promoted(run([heading, "動画の提出が必須です。"], "動画の提出が必須です", REQ), REQ)


def test_w6_control_a_condition_inside_the_quote_is_visible_and_does_not_demote():
    s = "海外在住の場合は、動画の提出が必須です。"
    assert_promoted(run([s], "海外在住の場合は、動画の提出が必須です", REQ), REQ)
    assert_promoted(run(["A demo video is required if the app uses a camera."], "A demo video is required if the app uses a camera", REQ), REQ)


# =====================================================================================================
# W7 例外・否定の語彙の穴。次の文の先頭や、同じ文の引用の外にあるのに拾えなかった語。
# =====================================================================================================
@pytest.mark.parametrize(
    "blocks,quote,kind",
    [
        (["動画の提出は必須です。", "もっとも、学生チームは対象外とします。"], "動画の提出は必須です", REQ),
        (
            ["動画の提出は必須です。", "この定めは、本ハッカソンに法人として参加する応募者が、事前に主催者へ書面で申請し、承認を得た場合には適用しません。"],
            "動画の提出は必須です",
            REQ,
        ),
        (
            ["動画の提出は必須です。", "前項の規定は、学生チームが主催者の承認を得て参加する場合であって、かつ審査員が認めたときには適用されない。"],
            "動画の提出は必須です",
            REQ,
        ),
        (["動画の提出は必須です。", "例外として、学生チームは提出を免除します。"], "動画の提出は必須です", REQ),
        (["動画の提出は必須です。", "特例として、学生チームは対象としません。"], "動画の提出は必須です", REQ),
        (["提出は必須だが、審査は無し。"], "提出は必須だが", REQ),
        (["動画の提出は必須とはされておらず、任意である。"], "動画の提出は必須とは", REQ),
        (["動画の提出は必須であったが、取りやめとなった。"], "動画の提出は必須であった", REQ),
        (["A demo video is required for all teams, other than student teams."], "A demo video is required for all teams", REQ),
        (["A demo video is required for all teams, apart from student teams."], "A demo video is required for all teams", REQ),
        (["A demo video is required. Student teams are exempt."], "A demo video is required", REQ),
        (["A demo video is required. Student teams are exempted from this."], "A demo video is required", REQ),
    ],
)
def test_w7_missing_exception_and_negation_words_are_found(blocks, quote, kind):
    assert_not_assertive(run(blocks, quote, kind))


# =====================================================================================================
# W8 箇条書きの手前切り。導入の文だけを要件として確定させると、条件（箇条書きの中身）が落ちる。
# =====================================================================================================
@pytest.mark.parametrize(
    "blocks,quote,kind",
    [
        (["次のいずれかに該当する場合は失格とします：", "重複応募", "虚偽の申告"], "次のいずれかに該当する場合は失格とします", PRO),
        (["応募者は以下の全てを満たすことが必要です", "日本国内に居住していること", "18歳以上であること"], "応募者は以下の全てを満たすことが必要です", REQ),
        (["次の行為を禁止します", "他者の著作物の無断使用", "虚偽の申告"], "次の行為を禁止します", PRO),
        (["提出物には下記の事項を必ず記載すること:", "氏名", "連絡先"], "提出物には下記の事項を必ず記載すること", REQ),
        (["Entries must meet all of the following conditions", "A demo video is attached", "The repository is public"], "Entries must meet all of the following conditions", REQ),
    ],
)
def test_w8_an_intro_sentence_whose_conditions_are_in_the_list_below_is_not_promoted(blocks, quote, kind):
    assert_not_assertive(run(blocks, quote, kind))


def test_w8_control_a_sentence_that_ends_properly_or_has_no_list_after_it_is_promoted():
    assert_promoted(run(["次のとおり提出物を提出すること。", "氏名", "連絡先"], "次のとおり提出物を提出すること", REQ), REQ)
    assert_promoted(run(["以下の規約に同意することが必須です。"], "以下の規約に同意することが必須です", REQ), REQ)
    # 箇条書きの項目そのものは、義務語があれば確定できる
    assert_promoted(run(["次の行為を禁止します", "他者の著作物を無断で使用してはならない。"], "他者の著作物を無断で使用してはならない", PRO), PRO)


@pytest.mark.parametrize(
    "blocks,quote",
    [
        (["【任意提出物】", "デモ動画をアップロードしてください。"], "デモ動画をアップロードしてください"),
        (["推奨事項", "動画は3分以内にまとめてください。"], "動画は3分以内にまとめてください"),
        (["Optional items", "Please upload a demo video."], "Please upload a demo video"),
        # 見出しと本文が同じブロック（プレーンテキストは、空行・箇条書きの記号でしかブロックを分けない）
        (["任意提出物 デモ動画をアップロードしてください。"], "任意提出物 デモ動画をアップロードしてください"),
        (["【任意】デモ動画をアップロードすること。"], "【任意】デモ動画をアップロードすること"),
    ],
)
def test_w8_a_weak_instruction_under_an_optional_heading_is_not_required(blocks, quote):
    r = run(blocks, quote, REQ)
    assert r.kind is OPT and r.demotion is D.REQUEST_WORDING and r.chips == (Chip.REQUEST_WORDING,)


def test_w8_control_a_required_heading_or_a_strong_word_keeps_the_kind():
    assert_promoted(run(["【必須提出物】", "デモ動画をアップロードしてください。"], "デモ動画をアップロードしてください", REQ), REQ)
    assert_promoted(run(["【任意提出物】", "説明文は必ず日本語で記載しなければならない。"], "説明文は必ず日本語で記載しなければならない", REQ), REQ)
    # 見出しは直前のブロックだけを見る（離れた見出しは見ない）
    assert_promoted(run(["推奨事項", "デモ動画の提出が望ましい。", "動画は3分以内にまとめること。"], "動画は3分以内にまとめること", REQ), REQ)


# =====================================================================================================
# W9 同じ引用が複数の文書にある。先頭の文書の文だけを見ると、後ろの文書にある例外が落ちる。
# =====================================================================================================
def test_w9_an_exception_in_a_later_document_demotes_a_quote_that_the_first_document_states_plainly():
    lp = doc("動画の提出は必須です。", doc_id="D1")
    faq = doc("動画の提出は必須です。", "ただし、学生チームを除く。", doc_id="D2")
    chk = checker(lp, faq)
    r = chk.resolve(raw("動画の提出は必須です", REQ), "R1").requirement
    assert r.demotion is D.NEGATION_OR_EXCEPTION
    assert r.span.doc_id == "D2" and r.span.original_span == "動画の提出は必須です。"  # 例外を持つ側の文を見せる


def test_w9_the_index_reports_the_other_documents_hits_without_changing_the_source():
    from app.quotes import DocIndex, Verified

    lp = doc("動画の提出は必須です。", doc_id="D1")
    faq = doc("動画の提出は必須です。ただし、学生チームを除く。", doc_id="D2")
    v = DocIndex([lp, faq]).verify("動画の提出は必須です")
    assert isinstance(v, Verified) and v.doc_id == "D1"  # 出典は登録順で先頭の文書
    assert [(o.doc_id, o.occurrences, len(o.spans)) for o in v.others] == [("D2", 1, 1)]
    only_faq = DocIndex([lp, faq]).verify("動画の提出は必須です", doc_id="D2")
    assert isinstance(only_faq, Verified) and only_faq.doc_id == "D2" and only_faq.others == ()  # 文書を指定すれば他は見ない


def test_w9_control_identical_restatements_keep_the_first_documents_span():
    lp = doc("動画の提出は必須です。", doc_id="D1")
    faq = doc("動画の提出は必須です。", doc_id="D2")
    r = checker(lp, faq).resolve(raw("動画の提出は必須です", REQ), "R1").requirement
    assert r.demotion is None and r.kind is REQ and r.span.doc_id == "D1"


def test_w9_a_short_quote_that_is_unique_in_each_document_but_means_different_things_is_checked_in_both():
    lp = doc("動画は3分以内とする。", doc_id="D1")
    faq = doc("ご案内の音声は3分以内とする、ただし字幕は除く。", doc_id="D2")
    r = checker(lp, faq).resolve(raw("3分以内とする", REQ), "R1").requirement
    assert r.demotion is D.NEGATION_OR_EXCEPTION


# =====================================================================================================
# W10 最終再検証のすり抜け。
# =====================================================================================================
def _tamper(chk: QuoteChecker, text: str, start: int, end: int, **kw) -> VerifiedRequirement:
    span = VerifiedSpan(doc_id="D1", start=start, end=end, original_span=text[start:end], occurrences=1)
    base = dict(
        seal=checker_mod._SEAL, req_id="R1", kind=REQ, declared_kind=REQ, span=span, demotion=None, chips=()
    )
    base.update(kw)
    return VerifiedRequirement(**base)


def test_w10_reverify_rejects_a_span_that_crosses_a_table_cell_separator():
    # 検証時は crosses_block で棄却される区間を、検証を通さずに作って昇格させる。| は VerifiedSpan の検査に引っかからない
    d = doc("項目 | 提出物は必須とする。")
    chk = checker(d)
    text = d.visible_text
    s, e = text.index("項目"), len(text)
    res = chk.reverify([_tamper(chk, text, s, e)])
    assert not res.ok and res.issues[0].reason is F.NOT_A_SENTENCE
    assert res.requirements[0].span is None  # 引用なしの推測へ落ちる


def test_w10_reverify_rejects_a_promotion_the_checker_never_issued():
    # 否定が文の中（引用の外）にあって降格された要件を、model_copy で「必須・降格なし」に書き換える。
    # 文全体を引用として再計算すると否定語が「引用の内側」になって通ってしまうので、発行の記録と突き合わせる
    d = doc("動画の提出は必須です（ただし、学生チームを除く）。")
    chk = checker(d)
    out = chk.resolve(raw("動画の提出は必須です", REQ), "R1")
    r = out.requirement
    assert r.demotion is D.NEGATION_OR_EXCEPTION  # 前提: 検証器は降格した
    forged = r.model_copy(update={"kind": REQ, "demotion": None, "chips": ()})
    res = chk.reverify([forged])
    assert not res.ok and res.issues[0].reason is F.NOT_ISSUED
    assert res.requirements[0].span is None and res.requirements[0].kind is SPEC_


def test_w10_crosses_separator_sees_cells_and_blocks_but_not_a_plain_span():
    from app.quotes import DocIndex

    d = doc("項目 | 提出物は必須とする。", "次のブロック。")
    idx = DocIndex([d])
    text = d.visible_text
    assert idx.crosses_separator("D1", 0, len(text)) and idx.crosses_separator("D1", 0, text.index("|") + 1)
    assert not idx.crosses_separator("D1", text.index("提出物"), text.index("。") + 1)
    assert not idx.crosses_separator("D1", 0, text.index("|"))  # | の直前まで


def test_w10_a_forgery_under_a_fresh_req_id_for_a_sentence_the_checker_demoted_is_caught_too():
    d = doc("動画の提出は必須です（ただし、学生チームを除く）。")
    chk = checker(d)
    r = chk.resolve(raw("動画の提出は必須です", REQ), "R1").requirement
    assert r.demotion is D.NEGATION_OR_EXCEPTION
    forged = r.model_copy(update={"req_id": "R2", "kind": REQ, "demotion": None, "chips": ()})
    res = chk.reverify([forged])
    assert not res.ok and res.issues[0].reason is F.NOT_ISSUED and res.issues[0].req_id == "R2"


def test_w10_control_what_the_checker_issued_passes_and_unknown_ids_fall_back_to_recomputation():
    d = doc("動画の提出は必須です。ただし、学生チームを除く。")
    chk = checker(d)
    good = chk.resolve(raw("動画の提出は必須です。ただし、学生チームを除く", REQ), "R1").requirement
    assert good.demotion is None
    res = chk.reverify([good])
    assert res.ok and res.requirements[0].reverified
    # 別の検証器（記録を持たない。再現・復元の場合）では、これまでどおり原文と突き合わせるだけで通る
    other = checker(d)
    assert other.reverify([good]).ok
    # 発行記録のある id でも、同じ内容を再び発行していれば通る（同じ id を2回発行しても合格が落ちない）
    again = chk.resolve(raw("動画の提出は必須です。ただし、学生チームを除く", REQ), "R1").requirement
    assert chk.reverify([good, again]).ok


def test_w10_control_relabeling_check_class_or_slot_after_the_fact_is_not_a_forgery():
    # 後段（Reader の check_class をコードで直す等）が model_copy で付け直す欄は、引用の判定に効かない＝発行の記録に含めない
    from app.contracts import CheckClass, Slot

    d = doc("動画の提出は必須です。")
    chk = checker(d)
    r = chk.resolve(raw("動画の提出は必須です", REQ), "R1").requirement
    relabeled = r.model_copy(update={"check_class": CheckClass.URL_PRESENT, "slot": Slot.NONE})
    assert chk.reverify([relabeled]).ok


# =====================================================================================================
# 第2ラウンド: 修正後の実装への攻撃（前の文を受ける例外・括弧の深さ・入力の大きさ）
# =====================================================================================================
def test_round2_a_sentence_that_refers_back_is_read_to_its_end_but_an_unrelated_one_is_not():
    # 「この動画は…」は前の文を受けるが、否定も例外も無い＝降格しない（受ける文を読むだけで、何でも降格はしない）
    assert_promoted(run(["動画の提出は必須です。", "この動画は審査員が視聴します。"], "動画の提出は必須です", REQ), REQ)
    # 受けない文は、先頭40字より後ろの否定を読まない（設計どおり。誤降格を避ける）
    long_tail = "審査結果は応募者全員へ後日メールで通知し、結果に関する個別の問い合わせには応じません。"
    assert_promoted(run(["動画の提出は必須です。", long_tail], "動画の提出は必須です", REQ), REQ)


def test_round2_an_exception_inside_the_quote_stays_visible_and_is_not_hidden():
    # 引用が例外ごと（2文）の場合は、画面に例外が出る＝降格しない（設計どおり）。表示される原文に例外が含まれることを固定する
    r = run(["動画の提出は必須です。ただし、学生チームを除く。"], "動画の提出は必須です。ただし、学生チームを除く", REQ)
    assert_promoted(r, REQ)
    assert "ただし、学生チームを除く" in r.span.original_span


def test_round2_a_hostile_run_of_openers_or_a_huge_block_neither_crashes_nor_stalls():
    import time

    t0 = time.perf_counter()
    for n in (70000, 200000):
        r = run(["（" * n + "動画の提出は必須とする。"], "動画の提出は必須とする", REQ)
        assert r.span is not None  # 閉じない括弧の中は1文＝長すぎる（160字超）か、ブロックの終わりまで
    body = "".join(f"第{i}条 提出物の説明は必須とする。" for i in range(8000))
    r = run([body], "第4000条 提出物の説明は必須とする", REQ)
    assert r.demotion is None and r.span.original_span == "第4000条 提出物の説明は必須とする。"
    assert time.perf_counter() - t0 < 10


def test_round2_the_final_recheck_reproduces_every_decision_on_a_rich_random_corpus():
    """肯定・否定・疑問・仮定・条件・導入・見出し・括弧・複数文書を混ぜた文書から切り出した引用を流す。
    昇格・降格のどれも、(1) 同じ検証器の最終再検証を通る、(2) 記録の無い検証器でも通る、(3) 拡張した文は再び拡張しても同じ区間。"""
    import random
    import re

    from app.contracts import InjectionSignal
    from app.quotes.sentence import snap_to_sentence

    frag = [
        "動画の提出は必須です", "他者の著作物を使用してはならない", "必須としません", "義務はありません", "提出すること", "ご遠慮ください",
        "必須ですか？", "予定です", "仮に", "例えば", "ただし、", "なお、", "を除く", "海外在住の場合は、", "この定めは、", "適用しません",
        "次の事項を", "以下の", "：", "【任意提出物】", "No demo video is required", "A demo video is required", "must not", "unless",
        "「提出は必須です。」と誤解されがちですが、", "（注：", "）", "「", "」", "。", "、", "|", "〔注入疑い〕", " ", "\n",
    ]
    rnd = random.Random(20261003)
    checked = 0
    for _ in range(250):
        docs = []
        for di in range(rnd.randint(1, 3)):
            blks = ["".join(rnd.choice(frag) for _ in range(rnd.randint(2, 14))) for _ in range(rnd.randint(1, 5))]
            text = SEP.join(blks)
            sigs = tuple(
                InjectionSignal(pattern_id="inj.test", doc_id=f"D{di + 1}", visible=True, start=m.start(), end=m.end())
                for m in re.finditer("〔注入疑い〕", text)
            )
            docs.append(doc(*blks, doc_id=f"D{di + 1}", injection_signals=sigs))
        chk = checker(*docs)
        fresh = checker(*docs)
        for _ in range(8):
            full = rnd.choice(docs).visible_text
            a = rnd.randrange(len(full))
            q = full[a : min(len(full), a + rnd.randint(6, 80))].replace(SEP, "")
            if not q.strip():
                continue
            r = chk.resolve(raw(q[:600], rnd.choice(list(Kind))), "R1", None).requirement
            checked += 1
            assert chk.reverify([r]).ok, (q, r)
            assert fresh.reverify([r]).ok, (q, r)
            if r.span is not None and r.demotion is not D.SENTENCE_TOO_LONG:
                text = next(d for d in docs if d.doc_id == r.span.doc_id).visible_text
                barriers = [(g.start, g.end) for g in next(d for d in docs if d.doc_id == r.span.doc_id).injection_signals]
                assert snap_to_sentence(text, r.span.start, r.span.end, barriers) in {(r.span.start, r.span.end)} or r.declared_kind is SPEC_
    assert checked > 800
