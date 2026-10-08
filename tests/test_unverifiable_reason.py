"""検査できないクラス（check_class=none）の確認不能の理由コード: 関門（checks/unverifiable_reason）と判定表への組み込み。

方針は「保守的」: 確信できる言い回しだけを HUMAN_ONLY／FUTURE／NOT_PUBLIC にし、外れたら OUT_OF_SCOPE（関門が無かった時と同じ）。
誤って別の理由に倒れる方が、OUT_OF_SCOPE に残るより悪い。
"""
import json
from collections import Counter

import pytest

import app.contracts as C
from app.adjudicate import adjudicate
from app.checks.unverifiable_reason import unverifiable_reason
from app.textsafe import BLOCK_SEP
from app.web.replay import REPLAY_DIR, load_bundle, rejudge
from tests.factories import make_doc, make_verified

U = C.UnverifiableReason
K = C.Kind
L = C.VerdictLabel

HUMAN, FUTURE, NOT_PUBLIC, OUT = U.HUMAN_ONLY, U.FUTURE, U.NOT_PUBLIC, U.OUT_OF_SCOPE

# --- 代表の文（正例）: 一般の言い回しで書いた、同梱の記録とは別の文 -----------------------------------------------------
POSITIVE = [
    # 参加資格・本人の条件
    ("参加者は満20歳以上の方に限ります。", K.REQUIRED, HUMAN),
    ("海外に在住の方も参加できます。", K.REQUIRED, HUMAN),
    ("1チームの人数は5名以内とすること。", K.REQUIRED, HUMAN),
    ("メンバーは3人以上で構成すること。", K.REQUIRED, HUMAN),
    # 登録・申込・提出の手続き
    ("参加を希望する方は、締切までに申し込んでください。", K.REQUIRED, HUMAN),
    ("作品は11月3日 12:00までに提出すること。", K.REQUIRED, HUMAN),
    ("エントリーフォームから応募してください。", K.REQUIRED, HUMAN),
    # ダッシュボード・フォームの記入欄
    ("ダッシュボードの「概要」項目にプロジェクトの説明を入力してください。", K.REQUIRED, HUMAN),
    ("申込フォームに連絡先を記入のうえ送信してください。", K.REQUIRED, HUMAN),
    # 費用・環境の注意
    ("無料枠を超えると料金が発生しますので、ご注意ください。", K.REQUEST, HUMAN),
    ("不要なリソースは、費用がかかるため削除してください。", K.REQUEST, HUMAN),
    # 任意の案内
    ("交流会への参加は任意です。", K.OPTIONAL, HUMAN),
    ("SNSでの発信もお気軽にどうぞ。", K.OPTIONAL, HUMAN),
    # 提出後・期間中の約束
    ("提出後の修正はご遠慮ください。", K.REQUEST, FUTURE),
    ("審査期間中は、公開したリポジトリを削除しないでください。", K.PROHIBITED, FUTURE),
    ("結果発表までの間は、提出物の内容を変更しないでください。", K.REQUIRED, FUTURE),
    ("提出時点の状態を最終審査まで維持すること。", K.REQUIRED, FUTURE),
    # 非公開の情報が要る
    ("社内の資料に基づいて作成した成果物であること。", K.REQUIRED, NOT_PUBLIC),
    ("非公開のリポジトリの場合は、審査担当に閲覧権限を付与すること。", K.REQUIRED, NOT_PUBLIC),
]


@pytest.mark.parametrize(("quote", "kind", "want"), POSITIVE)
def test_representative_sentences_get_their_reason(quote, kind, want):
    assert unverifiable_reason(quote, kind) is want


# --- 負例: 誤って割り当ててはいけない（OUT_OF_SCOPE のまま）-----------------------------------------------------------------
NEGATIVE = [
    # 断片・総括・短すぎる引用
    ("以下の必須条件をすべて満たしている必要があります。", K.REQUIRED),
    ("以下のいずれかを1つ以上使用してください。", K.REQUIRED),
    ("参加を希望する方は、締切までに申し込んで", K.REQUIRED),  # 文が途中で切れた断片
    ("登録する。", K.REQUIRED),  # 短すぎて文脈が無い
    ("", K.REQUIRED),
    # 検査する側の話題（提出物そのもの・審査員の見え方）。手続きや記入欄と言ってはいけない
    ("提出物のURLは、審査員がログインなしで開けること。", K.REQUIRED),
    ("審査員がアカウント登録なしで閲覧できるようにしてください。", K.REQUIRED),
    ("ログインフォームにテストアカウントの情報を入力してください。", K.REQUIRED),
    # 検査できる要件（字数・語の有無）の言い回し
    ("提出物の説明は500字以内とすること。", K.REQUIRED),
    ("READMEに利用手順を記載すること。", K.REQUIRED),
    ("画面と説明は日本語を基本にしてください。", K.REQUEST),
    # 否定・条件つきで意味が逆になる文
    ("参加登録は不要です。", K.REQUIRED),
    ("アカウント登録なしで利用できること。", K.REQUIRED),
    ("ユーザー登録をせずに、全機能を試せること。", K.REQUIRED),
    ("機密情報を含む資料を提出物に載せてはならない。", K.PROHIBITED),
    ("非公開のリポジトリを使用してはいけません。", K.PROHIBITED),
    ("社内の資料を含めないこと。", K.PROHIBITED),
    ("提出物は必須の項目を満たすこと。", K.OPTIONAL),  # 任意と言いながら「必須」を含む文は任意の案内と見ない
    # 道具が検査していない提出物の中身（人が読む説明）
    ("主要機能がモックではなく、実際に実装されていること。", K.REQUEST),
    ("ソーシャルログインが必須のログイン方法は避けてください。", K.PROHIBITED),
]


@pytest.mark.parametrize(("quote", "kind"), NEGATIVE)
def test_uncertain_sentences_stay_out_of_scope(quote, kind):
    assert unverifiable_reason(quote, kind) is OUT


def test_a_deadline_phrase_is_not_a_promise():
    # 「期間中に提出」は手続きの期限であって、提出後の約束ではない（FUTURE にしない）
    assert unverifiable_reason("応募期間中に作品を提出してください。", K.REQUIRED) is not FUTURE
    assert unverifiable_reason("期日までにご登録ください。", K.REQUIRED) is HUMAN


def test_the_gate_uses_only_the_quote_and_the_kind_and_always_returns_a_known_code():
    allowed = {HUMAN, FUTURE, NOT_PUBLIC, OUT}
    for quote, kind, _ in POSITIVE:
        assert unverifiable_reason(quote, kind) in allowed
    for kind in K:
        assert unverifiable_reason("まったく関係のない、ふつうの文章です。", kind) in allowed


# --- 同梱 REPLAY の手作業の分類（参考。仕様ではない）との一致 -------------------------------------------------------------
_TABLE = {
    "lp_self": "R1 cost, R2 cost, R3 procedure, R4 eligibility, R6 procedure, R7 eligibility, R8 fragment, R10 fragment, R11 procedure, "
    "R12 procedure, R13 field, R14 tool_gap, R15 tool_gap, R16 field, R17 optional, R18 field, R19 promise, R20 promise, R22 optional, "
    "R23 procedure, R26 procedure, R30 procedure, R32 field, R33 field, R36 field, R37 tool_gap, R38 promise, R39 promise, R40 promise, "
    "R41 eligibility, R42 fragment",
    "sample_defect": "R1 procedure, R4 eligibility, R6 optional, R8 procedure, R9 eligibility, R10 tool_gap",
    "sample_injection": "R1 procedure, R4 eligibility, R5 optional, R7 procedure, R8 eligibility, R9 tool_gap",
}
_KIND_TO_CODE = {"promise": FUTURE, "fragment": OUT, "tool_gap": OUT}  # 他（eligibility・procedure・field・cost・optional）は HUMAN_ONLY


def _expected(preset: str) -> dict[str, U]:
    out = {}
    for item in _TABLE[preset].split(", "):
        rid, cls = item.split()
        out[rid] = _KIND_TO_CODE.get(cls, HUMAN)
    return out


def _gate_results(preset: str) -> dict[str, tuple[U, U]]:
    """関門に来る要件（check_class=none の確認不能）だけ: req_id → (正解表, 関門の出力)。"""
    rec = load_bundle(REPLAY_DIR / f"{preset}.json").record
    want = _expected(preset)
    return {
        r.req_id: (want[r.req_id], unverifiable_reason(r.span.original_span, r.kind))
        for r in rec.requirements
        if r.span is not None and r.check_class is C.CheckClass.NONE and r.kind is not K.SPECULATIVE and r.req_id in want
    }


@pytest.mark.parametrize("preset", sorted(_TABLE))
def test_against_the_hand_classified_table_nothing_lands_on_a_wrong_reason(preset):
    results = _gate_results(preset)
    assert results
    wrong = {rid: got for rid, (want, got) in results.items() if got is not want and got is not OUT}
    assert wrong == {}  # 外れた分は OUT_OF_SCOPE に倒れていること。誤って別の理由に倒れた分は 0 件


def test_the_hand_classified_table_agreement_is_not_a_regression():
    agree = total = 0
    for preset in _TABLE:
        for want, got in _gate_results(preset).values():
            total += 1
            agree += want is got
    assert total >= 30 and agree / total >= 0.9  # 現状、関門に来る 36 件中 34 件が一致。残り 2 件（R32・R36）は OUT_OF_SCOPE に倒れている


# --- 判定表への組み込み ------------------------------------------------------------------------------------------------
def _verdict(quote: str, kind: K = K.REQUIRED, check_class: C.CheckClass = C.CheckClass.NONE) -> C.Verdict:
    doc = make_doc("D1", quote + BLOCK_SEP + "別の文です。")
    req = make_verified("R1", doc=doc, needle=quote, kind=kind, check_class=check_class)
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(doc.meta(),)))
    return v


GATE_TEXT = {
    HUMAN: "提出物のURLからは確かめられない条件です。ご自身で確認してください。",
    FUTURE: "提出後の約束や将来の事項で、今は検査できません。ご自身で守ってください。",
    NOT_PUBLIC: "非公開の情報が要るため、この道具は検査していません。ご自身で確認してください。",
    OUT: "この道具では検査していません。要項を読んで、ご自身で確認してください。",
}


@pytest.mark.parametrize(("quote", "kind", "want"), [POSITIVE[4], POSITIVE[13], POSITIVE[17], NEGATIVE[0] + (OUT,)])
def test_a_none_class_requirement_gets_the_code_and_one_fixed_sentence_per_code(quote, kind, want):
    v = _verdict(quote, kind)
    assert v.label is L.UNVERIFIABLE and v.reason_code is want
    assert v.reason == GATE_TEXT[want]
    assert not v.evidence


def test_the_fixed_sentences_embed_nothing_from_the_quote():
    for quote, kind, _ in POSITIVE:
        v = _verdict(quote, kind)
        assert v.reason in GATE_TEXT.values()
        assert not any(tok in v.reason for tok in ("20", "http", "11月", "5名"))


def test_other_out_of_scope_paths_are_unchanged():
    # class_screen（引用が検査の内容と合わない）は、関門を通らず従来の文と OUT_OF_SCOPE のまま
    v = _verdict("交流会への参加は任意です。", K.REQUIRED, C.CheckClass.LENGTH_LIMIT)
    assert v.reason_code is OUT
    assert v.reason == "この要件の引用は、割り当てられた検査の内容と合わないため、検査の結果を適用しません。"
    # 語が在ることを確かめる検査は禁止の要件に当てはまらない（向きが逆）
    v = _verdict("テストアカウントの案内を記載してはならない。", K.PROHIBITED, C.CheckClass.GUIDANCE_PRESENT)
    assert v.reason_code is OUT and "禁止の要件には当てはまりません" in v.reason


def test_a_speculative_requirement_is_still_a_reference_not_a_gated_one():
    v = _verdict("参加を希望する方は、締切までに申し込んでください。", K.SPECULATIVE)
    assert v.label is L.REFERENCE and v.reason_code is None


# --- 同梱 REPLAY: ラベルと件数が変わらず、記録が今のコードの再判定と一致する -------------------------------------------------------
@pytest.mark.parametrize("preset", sorted(_TABLE))
def test_the_bundled_replay_is_what_the_current_code_judges_and_labels_and_counts_hold(preset):
    rec = load_bundle(REPLAY_DIR / f"{preset}.json").record
    again = rejudge(rec)  # ラベルが変わるなら例外
    assert again.verdicts == rec.verdicts


# この変更の前（第7弾の main）の同梱記録のラベル別の件数。理由コードと文だけが変わり、ラベルと件数は変わらない
_LABEL_COUNTS_BEFORE = {
    "lp_self": {"参考": 6, "確認不能": 29, "適合": 5},
    "sample_defect": {"不適合": 3, "推定適合": 1, "確認不能": 6},
    "sample_injection": {"不適合": 3, "確認不能": 6},
}


@pytest.mark.parametrize("preset", sorted(_TABLE))
def test_the_label_counts_of_the_bundled_replays_did_not_change(preset):
    rec = load_bundle(REPLAY_DIR / f"{preset}.json").record
    assert dict(Counter(v.label.value for v in rec.verdicts)) == _LABEL_COUNTS_BEFORE[preset]


def test_the_unverifiable_reasons_of_the_bundled_replays_are_now_told_apart():
    codes = Counter()
    for preset in _TABLE:
        for v in load_bundle(REPLAY_DIR / f"{preset}.json").record.verdicts:
            if v.label is L.UNVERIFIABLE:
                codes[v.reason_code] += 1
    assert codes[HUMAN] > 0 and codes[FUTURE] > 0
    assert set(codes) <= {HUMAN, FUTURE, NOT_PUBLIC, OUT, U.NO_EVIDENCE}


def test_the_bundled_replay_files_use_the_agreed_words():
    for p in REPLAY_DIR.glob("*.json"):
        text = p.read_text(encoding="utf-8")
        data = json.loads(text)
        shown = [v["reason"] for v in data["verdicts"]] + [e["label"] for v in data["verdicts"] for e in v["evidence"]]
        assert not any("本文" in s or "原文" in s for s in shown)
