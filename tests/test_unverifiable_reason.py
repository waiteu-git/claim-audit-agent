"""検査できないクラス（check_class=none）の確認不能の理由コード: 関門（checks/unverifiable_reason）と判定表への組み込み。

方針は「保守的」: 確信できる言い回しだけを HUMAN_ONLY／FUTURE／NOT_PUBLIC にし、外れたら OUT_OF_SCOPE（関門が無かった時と同じ）。
誤って別の理由に倒れる方が、OUT_OF_SCOPE に残るより悪い（利用者に間違った次の一手を示す）。
そのため、否定・不要・許可・禁止・提出物の機能の記述は最初に OUT_OF_SCOPE へ落とし、通すのは確信できる言い回しだけにしてある。
下の負例は、取り込み前の敵対レビューで確認された誤分類の文（実際に誤って倒れた文）をそのまま回帰表にしたもの。
"""
import ast
import json
import re
import shutil
from collections import Counter
from pathlib import Path

import pytest

import app.checks.unverifiable_reason as gate
import app.contracts as C
import app.web.replay as replay
from app.adjudicate import GATE_REASON_TEXTS, adjudicate
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
    ("チームは2名から5名で構成してください。", K.REQUIRED, HUMAN),
    ("1チームの人数は最大5名です。", K.REQUIRED, HUMAN),
    ("申請者は法人であること。", K.REQUIRED, HUMAN),
    ("高校生以上の方が対象です。", K.REQUIRED, HUMAN),
    ("指定サービスのアカウントをお持ちの方に限ります。", K.REQUIRED, HUMAN),
    # 登録・申込・提出の手続き
    ("参加を希望する方は、締切までに申し込んでください。", K.REQUIRED, HUMAN),
    ("作品は11月3日 12:00までに提出すること。", K.REQUIRED, HUMAN),
    ("エントリーフォームから応募してください。", K.REQUIRED, HUMAN),
    ("作品は11月3日までに提出しなければなりません。", K.REQUIRED, HUMAN),
    ("参加には保護者の同意書の提出が必要です。", K.REQUIRED, HUMAN),
    # 手続きの期限（提出前）。FUTURE にせず、手続きとして人が確かめる
    ("最終発表までに作品を提出すること。", K.REQUIRED, HUMAN),
    ("この期間内に作品をご提出ください。", K.REQUIRED, HUMAN),
    ("結果発表までに必要書類をご提出ください。", K.REQUIRED, HUMAN),
    ("この期間内に参加登録を完了してください。", K.REQUIRED, HUMAN),
    ("応募期間中は、フォームから作品を提出してください。", K.REQUIRED, HUMAN),
    ("この期間内にご登録ください。", K.REQUIRED, HUMAN),
    ("結果発表までにご登録ください。", K.REQUIRED, HUMAN),
    # ダッシュボード・フォームの記入欄
    ("ダッシュボードの「概要」項目にプロジェクトの説明を入力してください。", K.REQUIRED, HUMAN),
    ("申込フォームに連絡先を記入のうえ送信してください。", K.REQUIRED, HUMAN),
    # 費用・環境の注意
    ("無料枠を超えると料金が発生しますので、ご注意ください。", K.REQUEST, HUMAN),
    ("不要なリソースは、費用がかかるため削除してください。", K.REQUEST, HUMAN),
    # 任意の案内
    ("交流会への参加は任意です。", K.OPTIONAL, HUMAN),
    ("SNSでの発信もお気軽にどうぞ。", K.OPTIONAL, HUMAN),
    # 提出後・期間中の約束（提出より後であることが明示され、守る動作が同じ文にあるものだけ）
    ("提出後の修正はご遠慮ください。", K.REQUEST, FUTURE),
    ("審査期間中は、公開したリポジトリを削除しないでください。", K.PROHIBITED, FUTURE),
    ("結果発表までの間は、提出物の内容を変更しないでください。", K.REQUIRED, FUTURE),
    ("提出時点の状態を最終審査まで維持すること。", K.REQUIRED, FUTURE),
    ("提出後は、公開したリポジトリの内容を変更してはならない。", K.REQUIRED, FUTURE),
    # 非公開の情報が要る（要る・求められる向きの文だけ）
    ("社内の資料に基づいて作成した成果物であること。", K.REQUIRED, NOT_PUBLIC),
    ("非公開のリポジトリの場合は、審査担当に閲覧権限を付与すること。", K.REQUIRED, NOT_PUBLIC),
]


@pytest.mark.parametrize(("quote", "kind", "want"), POSITIVE)
def test_representative_sentences_get_their_reason(quote, kind, want):
    assert unverifiable_reason(quote, kind) is want


# --- 負例: 誤って割り当ててはいけない（OUT_OF_SCOPE のまま）-----------------------------------------------------------------
# 指摘1: FUTURE が提出前の期限つき手続き・今すぐ行う確認・提出物の動作を「提出後の約束」にしてしまった（裸の語で当たっていた）
NEG_FUTURE_LOOKALIKE = [
    "参加登録期間中は、ダッシュボードからいつでも登録できます。",
    "提出期間中は、提出フォームから何度でも内容を更新できます。",
    "プロジェクトを提出後、完了ボタンを押してください。",
    "提出後、受付完了メールが届いていることを確認してください。",
    "提出時点で、リポジトリが公開されていること。",
    "提出時点で、必要事項がすべて入力されていること。",
    "締切後の提出は受け付けません。",
    "10月15日までの間は応募を受け付けています。",
    "ゲーム終了後にスコアを画面に表示すること。",
    "フォーム提出後に完了画面を表示すること。",
    "処理の終了後に一時ファイルを削除すること。",
]
# 指摘2・9・11: 否定・不要・許可・運営側の言い切りは、FUTURE／NOT_PUBLIC より先に OUT_OF_SCOPE へ落とす
NEG_PERMISSION_OPERATOR = [
    "提出後の修正は不要です。",
    "提出後の変更は不要です。",
    "提出後でも解説記事は投稿できます。",
    "解説記事の公開は提出後でも構いません。",
    "ただし、提出後の修正が認められる場合があります。",
    "最終審査の終了後に、結果を公開します。",
    "結果発表後、受賞者には改めて連絡します。",
    "非公開のリポジトリでも構いません。",
    # 許可の語だけが決め手になる文（語があっても、割り当てない）
    "提出後も別のブランチでの開発は構いませんが、デフォルトブランチは提出時点の状態を保ってください。",
    "ご登録の上、期日までにご提出いただければ構いません。",
    # 運営側の言い切りだけが決め手になる文
    "提出が必要な方には、運営から個別にご連絡します。",
    # 末尾の平叙の否定だけが決め手になる文（資格・手続きの語があっても、意味が逆かもしれない文は割り当てない）
    "18歳未満の方は参加できません。",
    "二重に参加登録することはできません。",
    "締切を過ぎた作品は提出すること自体できません。",
    "18歳未満の方は参加してはならない。",
    "18歳未満の方の参加は例外なし。",
]
# 指摘3・17: 「必要がありません」など、実際の要項で多い否定・不問・費用なしの言い回し（手続き・資格・費用の語があっても割り当てない）
NEG_EXEMPT = [
    "事前に参加登録をする必要がありません。",
    "参加の申し込みは必要ございません。",
    "応募フォームへの登録は必要ではありません。",
    "参加登録は必要ない。",
    "参加登録は必要なし。",
    "参加登録は必要としません。",
    "登録いただかなくても結構です。",
    "登録をいただく必要はございません。",
    "ユーザー登録の必要がなく、すぐに試せること。",
    "提出フォームへの入力は求めません。",
    "エントリーの必要はないものとします。",
    "申し込みの必要はございませんので、そのままご提出ください。",
    "ご登録いただく必要はございません。",
    "参加登録をしなくてもご応募いただけます。",
    "国籍・年齢・居住地は問いません。",
    "国籍を問わず、どなたでも参加できます。",
    "在住地を問わず参加できます。",
    "居住地は問いません。",
    "参加費やその他の費用は一切かかりません。",
    "利用料金は発生しません。",
    "利用にあたって、費用は一切かかりません。",
    "登録は必要ありません。",
    "申し込みの必要はありません。",
    "エントリーする必要はありません。",
    "居住地は問いません。国籍も不要です。",
    "費用は不要です。",
]
# 指摘4・10: 記入先の語と記入の動詞が同じ語で重なる文／提出物の画面・機能を作る・表示する要件
NEG_FIELD_LOOKALIKE = [
    "入力欄は3つ設けること。",
    "入力欄の幅は画面に合わせて調整されること。",
    "記入欄が画面からはみ出さないこと。",
    "登録フォームのデザインはシンプルにすること。",
    "提出フォームは日本語で表示されること。",
    "アップロードフォームは画像の形式を制限すること。",
    "作品の提出フォームのURLは別途お知らせします。",
    "お問い合わせフォームを作成すること。",
    "入力フォームには不正な値を弾く検証処理を設けること。",
    "管理用のダッシュボードを作成し、集計結果を表示すること。",
    "ユーザーが選択した項目に応じて、結果を表示すること。",
    "申込フォームの入力内容をデータベースに登録すること。",
    "アップロードフォームを提供し、画像を登録できること。",
    "フォームに入力された内容は、サーバー側でも検証すること。",
    "審査項目に対応する説明を作品ページに記載すること。",
    "アプリ内の入力フォームに入力したデータがダッシュボードに表示されること。",
    "検索結果のページに、選択した項目に関する情報を表示すること。",
]
# 指摘5: 「登録・応募」の語の後ろ15字の窓に動詞があれば手続き、としていた（提出物の機能・運営の方針文まで当たった）
NEG_PROCEDURE_LOOKALIKE = [
    "ユーザー登録機能を実装すること。",
    "会員登録ページを作成してください。",
    "応募作品には、必ず出典を明記してください。",
    "応募作品は日本語で作成してください。",
    "応募作品のURLは誰でも開ける状態にしてください。",
    "ご応募いただいた作品は、返却いたしません。",
    "ご応募いただいた個人情報は、運営目的以外には使用しません。",
    "ご応募いただいた作品の一部を広報に使用する場合があります。",
    "応募いただいた作品の著作権は応募者に帰属します。",
]
# 指摘6: 資格・費用の裸のキーワード（居住・国籍・N歳・課金・料金…）が、提出物の仕様や評価基準の文に当たっていた
NEG_ELIGIBILITY_COST_LOOKALIKE = [
    "ユーザーの居住地に応じて表示言語を切り替えること。",
    "対象年齢は6歳以上とし、アプリ内にその旨を表示すること。",
    "利用者の国籍によって差別的な扱いをしないこと。",
    "参加者5名以上のユーザーテストを実施し、結果を記載すること。",
    "課金要素を含まないこと。",
    "アプリ内課金を含めてはならない。",
    "ユーザーに料金を請求する機能を実装しないこと。",
    "請求書を発行する機能を実装すること。",
    "費用の見積もりをREADMEに記載すること。",
    "コスト削減に寄与するソリューションであること。",
    "ランニングコストを抑えた設計にすること。",
]
# 指摘7・9: NOT_PUBLIC は「非公開の情報が要る」向きだけ。提出物のプライバシー規則・禁止・対象外・失格・許可は割り当てない
NEG_NOT_PUBLIC_LOOKALIKE = [
    ("プライベートなデータを外部に送信する場合は、同意を得ること。", K.REQUIRED),
    ("ユーザーのプライベートなデータをサーバーに保存する場合は、暗号化すること。", K.REQUIRED),
    ("プライベートなデータを扱う場合は、取得の目的を画面に明示すること。", K.REQUIRED),
    ("非公開のデータの取り扱いには十分注意してください。", K.REQUEST),
    ("非公開のリポジトリは審査対象外です。", K.REQUIRED),
    ("非公開のリポジトリは審査の対象外です。", K.REQUIRED),
    ("プライベートなリポジトリのURLは提出できません。", K.REQUIRED),
    ("プライベートリポジトリのURLを提出した場合は失格とします。", K.REQUIRED),
    ("非公開リポジトリのURLを提出物に記載してはなりません。", K.PROHIBITED),
    ("社内の資料を含めないこと。", K.PROHIBITED),
    ("非公開のリポジトリを使用してはいけません。", K.PROHIBITED),
    ("機密情報を含む資料を提出物に載せてはならない。", K.PROHIBITED),
    ("社内資料の共有は禁止です。", K.PROHIBITED),
    ("社内資料を共有しないでください。", K.REQUEST),
]
# 指摘15: kind=任意 でも、提出物の中身（README・字数・公開・ログイン・画面）の話は「確かめられない条件」と言わない
NEG_OPTIONAL_LOOKALIKE = [
    "提出物の説明は500字以内が望ましい。",
    "リポジトリを公開にしておくことが望ましいです。",
    "審査員がログインできるテストアカウントを用意することが望ましい。",
    "READMEにアーキテクチャ図を載せると加点されます。",
    "READMEは日本語で記載することが望ましい。",
    "推奨環境は最新版の標準ブラウザです。",
    "デザイン面はユーザーに分かりやすいものが望ましい。",
    "READMEの記載は任意です。",
    "ログイン機能の実装は任意です。",
    "ライセンスの明記は任意です。",
    "リポジトリの公開は任意です。",
]
# 断片・総括・切れた引用: 文として読めないものは、語があっても割り当てない
NEG_FRAGMENT = [
    "以下の必須条件をすべて満たしている必要があります。",
    "以下のいずれかを1つ以上使用してください。",
    "参加を希望する方は、締切までに申し込んで",
    "登録する。",
    "",
    "18歳以上の方",
    "居住する方に限り",
    "ご登録の上",
    "参加者は日本国内に居住",
    "提出後の修正",
    "ご登録とご提出をお願い",
    "参加者は18歳以上の個人に限り",
    "提出後も開発を進めたい場合は別のブランチで行い、既定のブランチは提出時点の状態を保ち",
    "参加を希望する方は、締切までに申し込んでください、ただし、すでに…",  # 80字で切った引用（NFKC で「...」になる）
    "参加を希望する方は、締切までに申し込んでください、ただし、すでに...",
]
# 検査する側の話題（提出物そのもの・審査員の見え方）・検査できる要件（字数・語の有無）・提出物の中身
NEG_CHECKABLE_OR_PRODUCT = [
    "提出物のURLは、審査員がログインなしで開けること。",
    "審査員がアカウント登録なしで閲覧できるようにしてください。",
    "ログインフォームにテストアカウントの情報を入力してください。",
    "審査員がアクセスできるURLをご登録ください。",
    "提出物の説明は500字以内とすること。",
    "READMEに利用手順を記載すること。",
    "画面と説明は日本語を基本にしてください。",
    "参加登録は不要です。",
    "アカウント登録なしで利用できること。",
    "ユーザー登録をせずに、全機能を試せること。",
    "主要機能がモックではなく、実際に実装されていること。",
    "ソーシャルログインが必須のログイン方法は避けてください。",
]

_NEG_BY_KIND_DEFAULT = K.REQUIRED
NEGATIVE: list[tuple[str, K]] = (
    [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_FUTURE_LOOKALIKE]
    + [(q, K.OPTIONAL if "構いません" in q else _NEG_BY_KIND_DEFAULT) for q in NEG_PERMISSION_OPERATOR]
    + [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_EXEMPT]
    + [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_FIELD_LOOKALIKE]
    + [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_PROCEDURE_LOOKALIKE]
    + [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_ELIGIBILITY_COST_LOOKALIKE]
    + list(NEG_NOT_PUBLIC_LOOKALIKE)
    + [(q, K.OPTIONAL) for q in NEG_OPTIONAL_LOOKALIKE]
    + [(q, _NEG_BY_KIND_DEFAULT) for q in NEG_FRAGMENT]
    + [(q, K.PROHIBITED if "避けて" in q else _NEG_BY_KIND_DEFAULT) for q in NEG_CHECKABLE_OR_PRODUCT]
    + [("提出物は必須の項目を満たすこと。", K.OPTIONAL)]  # 任意と言いながら「必須」を含む文は任意の案内と見ない
)


@pytest.mark.parametrize(("quote", "kind"), NEGATIVE)
def test_uncertain_sentences_stay_out_of_scope(quote, kind):
    assert unverifiable_reason(quote, kind) is OUT


def test_a_deadline_phrase_is_not_a_promise():
    # 「期間中に提出」「〜までに提出・登録」は手続きの期限であって、提出後の約束ではない（FUTURE にしない）
    assert unverifiable_reason("応募期間中に作品を提出してください。", K.REQUIRED) is not FUTURE
    assert unverifiable_reason("期日までにご登録ください。", K.REQUIRED) is HUMAN
    assert unverifiable_reason("応募期間中は、何度でもご提出いただけます。", K.REQUIRED) is not FUTURE


def test_the_future_reason_needs_a_time_after_submission_and_a_promise_in_the_same_sentence():
    # 提出より後であることの明示だけ（約束が無い）／約束の動詞だけ（時点が無い）では、どちらも FUTURE にしない
    assert unverifiable_reason("提出後に結果をメールでお知らせします。", K.REQUIRED) is not FUTURE
    assert unverifiable_reason("リポジトリの内容は変更しないでください。", K.REQUIRED) is not FUTURE
    assert unverifiable_reason("提出後はリポジトリの内容を変更しないでください。", K.REQUIRED) is FUTURE


def test_not_public_is_never_given_to_a_prohibited_requirement():
    q = "非公開のリポジトリの場合は、審査担当に閲覧権限を付与すること。"
    assert unverifiable_reason(q, K.REQUIRED) is NOT_PUBLIC
    assert unverifiable_reason(q, K.PROHIBITED) is not NOT_PUBLIC  # 禁止の向きの要件に「非公開の情報が要る」とは言わない


def test_the_gate_returns_one_of_the_four_codes_for_every_kind():
    allowed = {HUMAN, FUTURE, NOT_PUBLIC, OUT}
    for quote, _, _ in POSITIVE:
        for kind in K:
            assert unverifiable_reason(quote, kind) in allowed
    for kind in K:
        assert unverifiable_reason("まったく関係のない、ふつうの文章です。", kind) is OUT


# --- ガードが決め手になっていること（外すと負例のどれかが割り当てに倒れる）----------------------------------------------------------
_NEVER = re.compile(r"(?!)")


@pytest.mark.parametrize(
    "guard",
    ["_EXEMPT", "_PERMISSION", "_OPERATOR", "_NEG_END", "_PRODUCT", "_PRODUCT_ACCESS", "_NOT_PUBLIC_BLOCK", "_OPTIONAL_CONTENT"],
)
def test_every_guard_is_decisive_for_at_least_one_negative(monkeypatch, guard):
    assert hasattr(gate, guard), guard
    monkeypatch.setattr(gate, guard, _NEVER)
    flipped = [q for q, k in NEGATIVE if unverifiable_reason(q, k) is not OUT]
    assert flipped, f"{guard} を外しても負例が変わらない（このガードを守るテストが無い）"


def test_the_fragment_guard_is_decisive_for_at_least_one_negative(monkeypatch):
    monkeypatch.setattr(gate, "_is_fragment", lambda flat: False)
    flipped = [q for q, k in NEGATIVE if unverifiable_reason(q, k) is not OUT]
    assert flipped, "断片のガードを外しても負例が変わらない"


def test_the_order_of_the_stages_is_pinned():
    # 否定・不要・許可は、費用・資格・FUTURE の語より先に見る（順序を入れ替えると誤って割り当てる文）
    assert unverifiable_reason("費用は不要です。", K.REQUIRED) is OUT
    assert unverifiable_reason("提出後の修正は不要です。", K.REQUIRED) is OUT
    # 断片は、FUTURE の語より先に見る
    assert unverifiable_reason("提出時点の状態を最終審査まで維持", K.REQUIRED) is OUT


# --- 語彙ごとの決め手（ガードの語を1つずつ外しても、どれかの文が割り当てに倒れる／割り当ての語を外すと、正例が落ちる）-------------------------------
_HUMAN_BAIT = "ご登録の上、期日までにご提出ください。"  # ガードが無ければ HUMAN_ONLY になる手続きの文
_NP_BAIT = "非公開のリポジトリの場合は、審査担当に閲覧権限を付与すること。"  # ガードが無ければ NOT_PUBLIC になる文

# ガードの語（1句に1つの語だけが入るように書く）。「句。」を手続きの文の前に置いても、OUT_OF_SCOPE のままであること
GUARD_PHRASES: dict[str, list[str]] = {
    "_EXEMPT": [
        "手数料は不要です", "確認の必要がありません", "追加の書類を必要としません", "追加の書類を必要とせず",
        "再度確認しなくても提出できる", "再度確認しなくてよい", "年齢は問いません", "年齢は不問とする",
        "確認の必要もありません", "確認の必要ではありません", "確認の必要じゃない", "確認の必要ない", "確認の必要なし", "確認の必要なく提出できる",
        "追加の書類を必要としない", "年齢は問わない", "年齢を問わず",
        "費用はかかりません", "費用はかからない", "費用は発生しません", "費用は発生しない", "費用は生じません", "費用は生じない",
        "追加の提出は求めません", "追加の提出は求めない", "負担は課しません", "負担は課さない", "手数料はいりません", "手数料は要りません",
    ],  # fmt: skip
    "_PERMISSION": [
        "どちらでも構いません", "どちらでもかまいません", "どちらでも構わない", "差し支えがある場合", "どちらでも問題ありません",
        "それで問題ない", "例外が認められる", "例外を認めます", "例外を認めて", "事前の許可", "例外は許されている", "誤差を許容する",
        "再提出を可とします（1回まで）", "どちらでもよい", "確認してもよい", "確認しても結構とする", "どちらでも結構とする", "それで結構です",
    ],  # fmt: skip
    "_OPERATOR": ["結果を公開します", "結果を公開いたします", "結果を公開しました", "記念品を差し上げます"],
    "_PRODUCT": [
        "検索を実装すること", "機能の一覧", "アプリ内の通知", "アプリの名称", "ホーム画面", "システム内の履歴", "ユーザーの名前",
        "利用者の名前", "APIの名称", "UIの配色", "UXの工夫", "サーバーの場所", "フロントエンドの方針", "バックエンドの方針",
        "READMEの章立て", "ドキュメントの章立て", "設計の方針", "アーキテクチャ図", "ソースコードの量", "デザインの方針", "ブラウザの種類",
        "名前を表示すること", "名前を表示させる", "名前が表示されること", "名前を表示できる", "結果の出力", "入力内容を検証すること", "結果の処理", "フレームワークの選定", "ライブラリの選定", "モックの利用",
    ],  # fmt: skip
    "_PRODUCT_ACCESS": [
        "審査員の端末", "審査委員会の資料", "閲覧の履歴", "アクセスの回数", "テストアカウントの数", "認証情報の扱い", "パスワードの長さ",
        "ログインページの色", "ログインフォームの色",
    ],  # fmt: skip
}
_NP_BLOCK_PHRASES = [
    "分からない点は質問してください", "迷わずに質問してください", "共有してはいけません", "混雑を避けて質問してください",
    "禁止事項は質問してください", "不可欠な点は質問してください", "お礼にはなりませんが質問してください", "お答えできませんが質問してください",
    "失格の場合は質問してください", "対象外の場合は質問してください", "除外した点は質問してください", "それ以外は質問してください",
    "お構いなく質問してください", "お問い合わせください", "不要な点は質問してください",
]  # fmt: skip
_OPTIONAL_CONTENT_WORDS = [
    "字数", "文字", "文章", "説明", "公開", "ログイン", "認証", "推奨環境", "リポジトリ", "ソース", "テスト", "加点", "評価",
    "デプロイ", "言語", "サイト", "URL", "スライド", "ライセンス", "コード",
]  # fmt: skip

GUARD_CASES: list[tuple[str, K, U]] = (
    [(_HUMAN_BAIT, K.REQUIRED, HUMAN), (_NP_BAIT, K.REQUIRED, NOT_PUBLIC), ("交流会に関する記載は任意です。", K.OPTIONAL, HUMAN)]  # 対照
    + [(f"{ph}。{_HUMAN_BAIT}", K.REQUIRED, OUT) for phrases in GUARD_PHRASES.values() for ph in phrases]
    + [(f"{_HUMAN_BAIT}結果を公開します", K.REQUIRED, OUT)]  # 句点の無い文末の運営側の言い切り
    + [(f"{ph}。{_NP_BAIT}", K.REQUIRED, OUT) for ph in _NP_BLOCK_PHRASES]
    + [(f"{w}に関する記載は任意です。", K.OPTIONAL, OUT) for w in _OPTIONAL_CONTENT_WORDS]
)


@pytest.mark.parametrize(("text", "kind", "want"), GUARD_CASES)
def test_every_guard_word_alone_keeps_a_bait_sentence_out_of_scope(text, kind, want):
    assert unverifiable_reason(text, kind) is want


# 割り当ての語（これを外すと、正例が OUT_OF_SCOPE に落ちる）。1文に1つの語だけが入るように書く
VOCAB_POSITIVE: list[tuple[str, K, U]] = (
    [  # 任意の案内の言い回し
        ("SNSでお気軽に発信してください。", K.OPTIONAL, HUMAN), ("SNSで自由に発信してください。", K.OPTIONAL, HUMAN),
        ("SNSでの発信もどうぞ。", K.OPTIONAL, HUMAN), ("SNSでの発信も歓迎です。", K.OPTIONAL, HUMAN),
        ("チャットでの交流が可能です。", K.OPTIONAL, HUMAN), ("SNSでの発信もできます。", K.OPTIONAL, HUMAN),
        ("ご希望の方は、SNSで発信してください。", K.OPTIONAL, HUMAN), ("発信を希望する方は、SNSを使ってください。", K.OPTIONAL, HUMAN),
        ("SNSでの発信がおすすめです。", K.OPTIONAL, HUMAN), ("SNSでの発信がお勧めです。", K.OPTIONAL, HUMAN),
    ]  # fmt: skip
    + [(f"対象は20歳以上の{w}です。", K.REQUIRED, HUMAN) for w in ("方", "者", "個人", "チーム", "メンバー", "学生", "生徒", "社会人", "法人", "団体", "企業")]
    + [  # 費用・環境の注意（語＋利用者の支払い・削除・上限に関する述語）
        ("課金が発生する場合があります。", K.REQUEST, HUMAN), ("料金が発生する場合があります。", K.REQUEST, HUMAN),
        ("費用がかかる場合があります。", K.REQUEST, HUMAN), ("請求が発生する場合があります。", K.REQUEST, HUMAN),
        ("無料枠を超える場合があります。", K.REQUEST, HUMAN), ("有料の場合は、事前にご注意ください。", K.REQUEST, HUMAN),
        ("費用はご自身の負担です。", K.REQUEST, HUMAN), ("課金される場合があります。", K.REQUEST, HUMAN),
        ("無料枠の超過にご留意ください。", K.REQUEST, HUMAN), ("有料のリソースは削除してください。", K.REQUEST, HUMAN),
        ("有料のサービスは停止してください。", K.REQUEST, HUMAN), ("料金にご注意ください。", K.REQUEST, HUMAN),
        ("有料プランへアップグレードしてください。", K.REQUEST, HUMAN), ("有料アカウントが必要です。", K.REQUEST, HUMAN),
    ]  # fmt: skip
    + [  # 提出後・期間中の約束（提出より後であることの明示と、守る動作）
        ("提出完了後は内容を変更しないでください。", K.REQUIRED, FUTURE), ("提出以降はリポジトリを削除しないでください。", K.REQUIRED, FUTURE),
        ("審査期間内は内容を変更しないでください。", K.REQUIRED, FUTURE), ("審査中はリポジトリを削除しないでください。", K.REQUIRED, FUTURE),
        ("審査後も内容を変更しないでください。", K.REQUIRED, FUTURE), ("結果発表まで内容を変更しないでください。", K.REQUIRED, FUTURE),
        ("結果発表後も内容を変更しないでください。", K.REQUIRED, FUTURE), ("受賞後も内容を変更しないでください。", K.REQUIRED, FUTURE),
        ("提出後も公開状態を保ち続けること。", K.REQUIRED, FUTURE), ("提出後は公開状態を保つこと。", K.REQUIRED, FUTURE),
        ("提出後も公開を継続すること。", K.REQUIRED, FUTURE), ("提出後も公開し続けてください。", K.REQUIRED, FUTURE),
    ]  # fmt: skip
    + [  # 非公開の情報が要る（審査する側がそれを見る・それに基づく）
        ("非公開のリポジトリは閲覧権限が必要です。", K.REQUIRED, NOT_PUBLIC), ("非公開のリポジトリはアクセス権が必要です。", K.REQUIRED, NOT_PUBLIC),
        ("非公開のリポジトリは、権限を付与してください。", K.REQUIRED, NOT_PUBLIC), ("非公開のリポジトリは、審査担当を招待してください。", K.REQUIRED, NOT_PUBLIC),
        ("非公開のリポジトリは、審査担当に共有してください。", K.REQUIRED, NOT_PUBLIC), ("非公開のリポジトリを審査担当に提供してください。", K.REQUIRED, NOT_PUBLIC),
        ("非公開のリポジトリの内容を開示してください。", K.REQUIRED, NOT_PUBLIC), ("非公開のリポジトリの内容を提示してください。", K.REQUIRED, NOT_PUBLIC),
        ("非公開のリポジトリを参照してください。", K.REQUIRED, NOT_PUBLIC), ("社内の資料をもとに作成すること。", K.REQUIRED, NOT_PUBLIC),
        ("社内の資料を元に作成すること。", K.REQUIRED, NOT_PUBLIC), ("社内の資料を用いて作成すること。", K.REQUIRED, NOT_PUBLIC),
        ("社内の資料を利用して作成すること。", K.REQUIRED, NOT_PUBLIC), ("社内の資料を使用して作成すること。", K.REQUIRED, NOT_PUBLIC),
        ("内部の資料に基づいて作成すること。", K.REQUIRED, NOT_PUBLIC),
    ]  # fmt: skip
    + [  # 手続き・資格の言い回し
        ("4名以内のチームで参加すること。", K.REQUIRED, HUMAN),
        ("作品は11月3日までに提出しなければならない。", K.REQUIRED, HUMAN), ("作品は11月3日までに提出しなくてはならない。", K.REQUIRED, HUMAN),
        ("期日までに参加登録をお願いいたします。", K.REQUIRED, HUMAN), ("期日までに参加登録をお願いします。", K.REQUIRED, HUMAN),
        # 文末の句点が無い箇条書きの1項目（文として読める終わり方）
        ("期日までにご登録ください", K.REQUIRED, HUMAN), ("作品は期日までに提出すること", K.REQUIRED, HUMAN),
        ("参加登録が必要です", K.REQUIRED, HUMAN), ("期日までに作品の提出をお願い申し上げます", K.REQUIRED, HUMAN),
        ("11月3日までに作品を提出しなければなりません", K.REQUIRED, HUMAN), ("作品は11月3日までに提出する必要がある", K.REQUIRED, HUMAN),
    ]  # fmt: skip
)


_FIELD_VERBS = ["記入", "記載", "入力", "選択", "添付", "回答", "送信"]
_FIELD_PLACES = ["ダッシュボードの項目", "申込フォーム", "入力欄", "記入欄", "「概要」項目", "「概要」欄"]
VOCAB_POSITIVE += (
    # 記入欄: 記入先の語ごと／動詞ごと／依頼の形ごと（記入先の語と動詞は別の文字列）
    [(f"{pl}に内容をご記入ください。", K.REQUIRED, HUMAN) for pl in _FIELD_PLACES]
    + [(f"ダッシュボードの項目に内容をご{v}ください。", K.REQUIRED, HUMAN) for v in _FIELD_VERBS]
    + [(f"ダッシュボードの項目に内容を{v}してください。", K.REQUIRED, HUMAN) for v in _FIELD_VERBS]
    + [
        ("ダッシュボードの項目に内容をご記入の上、お進みください。", K.REQUIRED, HUMAN),
        ("ダッシュボードの項目に内容をご記入のうえ、お進みください。", K.REQUIRED, HUMAN),
        ("ダッシュボードの項目に内容をご記入をお願いします。", K.REQUIRED, HUMAN),
        ("ダッシュボードの項目に内容を記入してください。", K.REQUIRED, HUMAN),
        ("フォームからお知らせください。", K.REQUIRED, HUMAN),
        ("フォームに画像をアップロードしてください。", K.REQUIRED, HUMAN),
        ("フォームにURLを貼り付けてください。", K.REQUIRED, HUMAN),
    ]  # fmt: skip
    # 手続き: 名詞ごと／依頼・義務の形ごと
    + [
        ("期日までにご登録ください。", K.REQUIRED, HUMAN), ("期日までに参加登録してください。", K.REQUIRED, HUMAN),
        ("期日までに参加を申し込んでください。", K.REQUIRED, HUMAN), ("期日までにエントリーしてください。", K.REQUIRED, HUMAN),
        ("期日までに応募してください。", K.REQUIRED, HUMAN), ("期日までに作品を提出してください。", K.REQUIRED, HUMAN),
        ("期日までに参加登録もお願いします。", K.REQUIRED, HUMAN), ("参加登録は必要です。", K.REQUIRED, HUMAN),
        ("作品を提出する必要があります。", K.REQUIRED, HUMAN), ("作品は11月3日までに提出しなければいけない。", K.REQUIRED, HUMAN),
        ("作品は11月3日までに提出しなければいけません。", K.REQUIRED, HUMAN), ("ご登録の上、お進みください。", K.REQUIRED, HUMAN),
        ("ご登録のうえ、お進みください。", K.REQUIRED, HUMAN), ("参加登録を完了してください。", K.REQUIRED, HUMAN),
    ]  # fmt: skip
    # 資格: 年齢の言い方／居住の言い方／人数の言い方／参加者が主語の形
    + [(f"対象は20歳{w}の方です。", K.REQUIRED, HUMAN) for w in ("以下", "未満", "以内")]
    + [
        ("国内に居住する方も参加できます。", K.REQUIRED, HUMAN), ("国内に在住している者も参加できます。", K.REQUIRED, HUMAN),
        ("国内に居住の個人も参加できます。", K.REQUIRED, HUMAN), ("国内に在住するチームも参加できます。", K.REQUIRED, HUMAN),
        ("国内に居住している人も参加できます。", K.REQUIRED, HUMAN),
    ]  # fmt: skip
    + [(f"{pre}は5名までです。", K.REQUIRED, HUMAN) for pre in ("チーム", "メンバー", "参加者", "人数")]
    + [(f"チームは5名{suf}です。", K.REQUIRED, HUMAN) for suf in ("以内", "以下", "以上", "未満")]
    + [("チームは5人までです。", K.REQUIRED, HUMAN), ("チームは2名から5名です。", K.REQUIRED, HUMAN), ("チームは2人から5人です。", K.REQUIRED, HUMAN)]
    + [(f"5名{suf}のチームで参加すること。", K.REQUIRED, HUMAN) for suf in ("まで", "以内", "以下", "以上", "未満")]
    + [("5人以内で参加すること。", K.REQUIRED, HUMAN), ("5名以内のチームを編成すること。", K.REQUIRED, HUMAN)]
    + [
        ("応募者は学生であること。", K.REQUIRED, HUMAN), ("代表者が成人でなければならない。", K.REQUIRED, HUMAN),
        ("申請者は法人に限ります。", K.REQUIRED, HUMAN), ("参加者が個人に限られます。", K.REQUIRED, HUMAN),
        ("20歳以上の方に限ります。", K.REQUIRED, HUMAN), ("学生の者のみ参加できます。", K.REQUIRED, HUMAN),
        ("成人の方が対象です。", K.REQUIRED, HUMAN), ("成人の方を対象とする。", K.REQUIRED, HUMAN), ("成人の者に限る。", K.REQUIRED, HUMAN),
    ]  # fmt: skip
    # 約束: 時点の言い方／守る動作の言い方
    + [
        ("審査期間は内容を変更しないでください。", K.REQUIRED, FUTURE),
        ("審査の終了後は内容を変更しないでください。", K.REQUIRED, FUTURE), ("審査まで内容を変更しないでください。", K.REQUIRED, FUTURE),
        ("提出後の修正はお控えください。", K.REQUEST, FUTURE), ("提出後も公開状態を継続すること。", K.REQUIRED, FUTURE),
        ("提出後は内容を変更しないこと。", K.REQUIRED, FUTURE), ("提出後は変更を加えないようお願いします。", K.REQUIRED, FUTURE),
    ]  # fmt: skip
    + [
        (f"提出後は{n}{mid}{end}。", K.REQUIRED, FUTURE)
        for n, mid, end in zip(
            ("変更", "修正", "編集", "更新", "削除", "解除", "停止", "閉鎖", "改変"),
            ("を加え", "を行わ", "をし", "し") * 3,
            ("ないでください", "ないこと", "ないでください") * 3,
        )
    ]
    + [
        (f"提出後は{n}{p}{v}{form}。", K.REQUIRED, FUTURE)
        for n, p, v, form in zip(
            ("変更", "修正", "編集", "更新", "削除", "解除", "停止", "閉鎖", "改変"),
            ("を", "は", "") * 3,
            ("し", "行っ", "加え", "") * 3,
            ("てはならない", "てはいけない", "てはなりません", "てはいけません") * 3,
        )
    ]
    # 非公開: 非公開の言い方／名詞の種類
    + [(f"{adj}のリポジトリは、審査担当に共有してください。", K.REQUIRED, NOT_PUBLIC) for adj in ("限定公開", "非公開", "プライベート", "private")]
    + [("プライベートなリポジトリは、審査担当に共有してください。", K.REQUIRED, NOT_PUBLIC)]
    + [(f"非公開の{n}を審査担当に共有してください。", K.REQUIRED, NOT_PUBLIC) for n in ("資料", "文書", "ドキュメント", "ソースコード")]
    + [(f"社内{n}を用いて作成すること。", K.REQUIRED, NOT_PUBLIC) for n in ("資料", "文書", "ドキュメント", "システム", "ネットワーク")]
    + [(f"内部の{n}に基づいて作成すること。", K.REQUIRED, NOT_PUBLIC) for n in ("資料", "文書", "ドキュメント")]
    + [("非公開のリポジトリは、権限を与えてください。", K.REQUIRED, NOT_PUBLIC)]
)


@pytest.mark.parametrize(("text", "kind", "want"), VOCAB_POSITIVE)
def test_every_vocabulary_entry_of_the_assigning_patterns_has_a_sentence_that_needs_it(text, kind, want):
    assert unverifiable_reason(text, kind) is want


# --- モデルが付ける値は関門の入力ではない ---------------------------------------------------------------------------------------
def _doc_for(quote: str):
    return make_doc("D1", quote + BLOCK_SEP + "別の文です。")


def _requirement(quote: str, kind: K = K.REQUIRED, **kw):
    return make_verified("R1", doc=_doc_for(quote), needle=quote, kind=kind, check_class=C.CheckClass.NONE, **kw)


def _verdict(quote: str, kind: K = K.REQUIRED, check_class: C.CheckClass = C.CheckClass.NONE, marks=(), **kw) -> C.Verdict:
    doc = _doc_for(quote)
    req = make_verified("R1", doc=doc, needle=quote, kind=kind, check_class=check_class, **kw)
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(doc.meta(),), marks=tuple(marks)))
    return v


_VARIANT_QUOTES = [
    ("ご登録の上、期日までにご提出ください。", K.REQUIRED),  # HUMAN_ONLY
    ("提出後はリポジトリの内容を変更しないでください。", K.REQUIRED),  # FUTURE
    ("社内の資料に基づいて作成した成果物であること。", K.REQUIRED),  # NOT_PUBLIC
    ("主要機能がモックではなく、実際に実装されていること。", K.REQUIRED),  # OUT_OF_SCOPE
    ("交流会への参加は任意です。", K.OPTIONAL),  # HUMAN_ONLY（任意）
]


@pytest.mark.parametrize(("quote", "kind"), _VARIANT_QUOTES)
def test_the_verdict_does_not_depend_on_any_value_the_model_attaches(quote, kind):
    base = _verdict(quote, kind)
    variants = []
    for slot in C.Slot:  # Slot は Reader（モデル）が付ける。全値で同じ判定
        variants.append(dict(slot=slot))
    for chips in ((), (C.Chip.NEGATION_OR_EXCEPTION,), (C.Chip.REQUEST_WORDING,), (C.Chip.NEGATION_OR_EXCEPTION, C.Chip.REQUEST_WORDING)):
        variants.append(dict(chips=chips))
    variants += [dict(reverified=True), dict(reverified=False)]
    if kind is K.OPTIONAL:  # 申告が必須で、コードが依頼文言のため任意に降格した要件（最終 kind は同じ任意）
        variants.append(dict(declared_kind=K.REQUIRED, demotion=C.DemotionReason.REQUEST_WORDING, chips=(C.Chip.REQUEST_WORDING,)))
    for kw in variants:
        assert _verdict(quote, kind, **kw) == base, kw


def test_kind_only_matters_for_optional_guidance_and_for_not_public():
    quotes = [q for q, _, _ in POSITIVE] + [q for q, _ in NEGATIVE] + [t for t, _, _ in VOCAB_POSITIVE]
    for q in quotes:
        base = unverifiable_reason(q, K.REQUIRED)
        for kind in (K.REQUEST, K.SPECULATIVE):  # この2つの kind は、結果を変えない
            assert unverifiable_reason(q, kind) is base, (q, kind)
        # 禁止の要件には「非公開の情報が要る」と言わない（NOT_PUBLIC → OUT_OF_SCOPE だけが起こりうる）
        assert unverifiable_reason(q, K.PROHIBITED) is (OUT if base is NOT_PUBLIC else base), q
        # 任意の案内（OUT_OF_SCOPE → HUMAN_ONLY だけが起こりうる）。文にも任意・自由の言い回しが要る
        opt = unverifiable_reason(q, K.OPTIONAL)
        assert opt is base or (base is OUT and opt is HUMAN and gate._OPTIONAL_CUE.search(q)), q


def test_the_gate_signature_takes_only_the_quote_and_the_final_kind():
    import inspect

    assert list(inspect.signature(unverifiable_reason).parameters) == ["quote", "kind"]


# --- Planner の確認不能の印は、検査できないクラスの理由を決められない -------------------------------------------------------------------
@pytest.mark.parametrize("code", [HUMAN, FUTURE, NOT_PUBLIC, OUT])
@pytest.mark.parametrize(("quote", "want"), [("ご登録の上、期日までにご提出ください。", HUMAN), ("主要機能がモックではなく、実際に実装されていること。", OUT)])
def test_a_planner_mark_cannot_choose_the_reason_of_a_none_class_requirement(code, quote, want):
    base = _verdict(quote)
    assert base.reason_code is want
    marked = _verdict(quote, marks=(C.UnverifiableMark(req_id="R1", reason_code=code, by_planner=True),))
    assert marked == base  # 理由コードも固定文も、関門が決めたまま


def test_a_mark_the_code_makes_still_decides_a_none_class_requirement():
    v = _verdict("ご登録の上、期日までにご提出ください。", marks=(C.UnverifiableMark(req_id="R1", reason_code=U.BUDGET),))
    assert v.reason_code is U.BUDGET  # 実行の上限など、コードが付ける印は従来どおり効く


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
# 保守的な関門が拾わない（OUT_OF_SCOPE に倒れる）と分かっている行。ここに無い行が外れたら退行
_KNOWN_MISSES = {("lp_self", "R32"), ("lp_self", "R36"), ("lp_self", "R39")}


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
    missed = set()
    for preset in _TABLE:
        for rid, (want, got) in _gate_results(preset).items():
            total += 1
            agree += want is got
            if want is not got:
                missed.add((preset, rid))
    assert total >= 30 and missed <= _KNOWN_MISSES  # 現状、関門に来る 36 件中 33 件が一致。外れた 3 件は OUT_OF_SCOPE に倒れている
    assert agree / total >= 0.9


# --- 判定表への組み込み ------------------------------------------------------------------------------------------------
GATE_TEXT = {
    HUMAN: "提出物のURLからは確かめられない条件です。ご自身で確認してください。",
    FUTURE: "提出後の約束や将来の事項で、今は検査できません。ご自身で守ってください。",
    NOT_PUBLIC: "非公開の情報が要るため、この道具は検査していません。ご自身で確認してください。",
    OUT: "この道具では検査していません。要項を読んで、ご自身で確認してください。",
}


@pytest.mark.parametrize(
    ("quote", "kind", "want"),
    [
        ("参加を希望する方は、締切までに申し込んでください。", K.REQUIRED, HUMAN),
        ("提出後の修正はご遠慮ください。", K.REQUEST, FUTURE),
        ("社内の資料に基づいて作成した成果物であること。", K.REQUIRED, NOT_PUBLIC),
        ("以下の必須条件をすべて満たしている必要があります。", K.REQUIRED, OUT),
    ],
)
def test_a_none_class_requirement_gets_the_code_and_one_fixed_sentence_per_code(quote, kind, want):
    v = _verdict(quote, kind)
    assert v.label is L.UNVERIFIABLE and v.reason_code is want
    assert v.reason == GATE_TEXT[want]
    assert not v.evidence


def test_the_set_of_gate_texts_is_exported_for_the_report():
    assert GATE_REASON_TEXTS == frozenset(GATE_TEXT.values())


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


def test_a_clipped_quote_is_never_given_a_specific_reason():
    # 同梱用に80字で切った引用（quote_clipped）は文の前半だけ。前半の語で理由を決めない
    quote = "参加を希望する方は、締切までに申し込んでください、ただし、すでに登録済みの方を除きます。"
    doc = make_doc("D1", quote + BLOCK_SEP + "別の文です。")
    clipped = quote[:30]
    req = make_verified("R1", doc=doc, needle=quote, kind=K.REQUIRED, check_class=C.CheckClass.NONE)
    req = req.model_copy(update={"span": req.span.model_copy(update={"original_span": clipped, "quote_clipped": True})})
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(doc.meta(),)))
    assert v.reason_code is OUT and v.reason == GATE_TEXT[OUT]


# --- 同梱 REPLAY: ラベルと件数が変わらず、記録（判定表とトレースの verdict イベント）が今のコードの再判定と一致する -------------------------------
@pytest.mark.parametrize("preset", sorted(_TABLE))
def test_the_bundled_replay_is_what_the_current_code_judges(preset):
    rec = load_bundle(REPLAY_DIR / f"{preset}.json").record
    again = rejudge(rec)  # ラベルが変わるなら例外
    assert again.verdicts == rec.verdicts
    assert again.events == rec.events


@pytest.mark.parametrize("preset", sorted(_TABLE))
def test_the_trace_verdict_events_agree_with_the_verdict_table(preset):
    rec = load_bundle(REPLAY_DIR / f"{preset}.json").record
    table = {v.req_id: (v.label, v.reason_code.value if v.reason_code else None) for v in rec.verdicts}
    events = [e for e in rec.events if e.type is C.TraceType.VERDICT]
    assert events
    for e in events:  # 画面のトレース欄は、このイベントの reason_code を表示する。表と食い違ってはならない
        assert (e.verdict, e.reason_code) == table[e.req_id], e.req_id


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
        data = json.loads(p.read_text(encoding="utf-8"))
        shown = [v["reason"] for v in data["verdicts"]] + [e["label"] for v in data["verdicts"] for e in v["evidence"]]
        assert not any("本文" in s or "原文" in s for s in shown)


# --- rejudge と --check / --rejudge の振る舞い ------------------------------------------------------------------------------------
def _stale(record_json: dict) -> dict:
    """この変更の前の記録に見立てる: 関門由来の確認不能を、旧来の理由コード・固定文に戻す（判定表とトレースの両方）。"""
    d = json.loads(json.dumps(record_json))
    stale_ids = set()
    for v in d["verdicts"]:
        if v["label"] == "確認不能" and v["reason_code"] in ("HUMAN_ONLY", "FUTURE", "NOT_PUBLIC") and v["reason"] in GATE_TEXT.values():
            v["reason_code"], v["reason"] = "OUT_OF_SCOPE", "検査できる範囲の外です。"
            stale_ids.add(v["req_id"])
    for e in d["events"]:
        if e["type"] == "verdict" and e["req_id"] in stale_ids:
            e["reason_code"] = "OUT_OF_SCOPE"
    assert stale_ids
    return d


def test_rejudge_rewrites_stale_reasons_and_the_trace_events_and_keeps_labels():
    for preset in sorted(_TABLE):
        good = load_bundle(REPLAY_DIR / f"{preset}.json").record
        text = (REPLAY_DIR / f"{preset}.json").read_text(encoding="utf-8")
        stale = replay.restore_saved_record(json.dumps(_stale(json.loads(text)), ensure_ascii=False))
        assert stale.verdicts != good.verdicts and stale.events != good.events  # 前提: 本当に古い記録
        again = rejudge(stale)
        assert again.verdicts == good.verdicts  # 理由コード・固定文が作り直される
        assert again.events == good.events  # トレースの verdict イベントの理由コードも作り直される
        assert [v.label for v in again.verdicts] == [v.label for v in stale.verdicts]


def test_rejudge_refuses_a_record_whose_labels_would_change():
    rec = load_bundle(REPLAY_DIR / "lp_self.json").record
    assert any(v.label is L.PASS for v in rec.verdicts)
    broken = rec.model_copy(update={"observations": ()})  # 観測が無ければ、適合だった要件は確認不能になる
    with pytest.raises(ValueError, match="ラベル"):
        rejudge(broken)


@pytest.mark.parametrize(("req_id", "forged"), [("R15", U.NEEDS_AUTH), ("R16", U.HUMAN_ONLY)])
def test_rejudge_refuses_a_change_of_reason_outside_the_gate(req_id, forged):
    # 検査の種類がある要件（R15: 観測が無く根拠なし／R16: 引用が検査と合わず範囲外）の確認不能の理由は、関門が決めるものではない。
    # 印などの入力が足りない記録を、黙って別の理由に書き換えない（ラベルが同じでも、理由コードが変わるなら拒否する）
    rec = load_bundle(REPLAY_DIR / "lp_self.json").record
    verdicts = tuple(v.model_copy(update={"reason_code": forged}) if v.req_id == req_id else v for v in rec.verdicts)
    forged_record = rec.model_copy(update={"verdicts": verdicts})
    assert [v.label for v in forged_record.verdicts] == [v.label for v in rec.verdicts]
    with pytest.raises(replay.RejudgeRefused, match="関門の外"):
        rejudge(forged_record)


def test_rejudge_refuses_a_record_made_with_planner_marks():
    rec = load_bundle(REPLAY_DIR / "sample_defect.json").record
    ev = rec.events[0].model_copy(update={"type": C.TraceType.TOOL_REQUEST, "name": C.ToolName.MARK_UNVERIFIABLE.value, "verdict": None})
    marked = rec.model_copy(update={"events": (ev, *rec.events[1:])})
    with pytest.raises(replay.RejudgeUnsupported):
        rejudge(marked)


def _copy_bundles(tmp_path: Path) -> None:
    for pid in ("lp_self", "sample_defect", "sample_injection"):
        shutil.copy(REPLAY_DIR / f"{pid}.json", tmp_path)


def test_check_reports_a_bundle_whose_verdicts_or_trace_events_are_stale(tmp_path):
    _copy_bundles(tmp_path)
    assert replay.check(tmp_path) == []
    for pid in ("sample_defect", "lp_self"):  # 実モデルの記録（取り込み）は再生成できない代わりに、今のコードの再判定と照らす
        p = tmp_path / f"{pid}.json"
        original = p.read_text(encoding="utf-8")
        p.write_text(json.dumps(_stale(json.loads(original)), ensure_ascii=False), encoding="utf-8")
        assert replay.check(tmp_path) == [p.name]
        p.write_text(original, encoding="utf-8")
        d = json.loads(original)  # 判定表は新しいのに、トレースの verdict イベントだけ古い
        ev = next(e for e in d["events"] if e["type"] == "verdict" and e["reason_code"] != "OUT_OF_SCOPE")
        ev["reason_code"] = "OUT_OF_SCOPE"
        p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
        assert replay.check(tmp_path) == [p.name]
        p.write_text(original, encoding="utf-8")
    assert replay.check(tmp_path) == []


def test_rejudge_command_computes_every_record_before_writing_any(tmp_path, monkeypatch, capsys):
    _copy_bundles(tmp_path)
    monkeypatch.setattr(replay, "REPLAY_DIR", tmp_path)
    first = tmp_path / "lp_self.json"
    stale_text = json.dumps(_stale(json.loads(first.read_text(encoding="utf-8"))), ensure_ascii=False)
    first.write_text(stale_text, encoding="utf-8")  # 先頭の記録は古い（書き直されるはず）
    last = tmp_path / "sample_injection.json"
    d = json.loads(last.read_text(encoding="utf-8"))
    fail = next(v for v in d["verdicts"] if v["label"] == "不適合")
    fail["label"], fail["reason_code"] = "確認不能", "NO_EVIDENCE"  # 末尾の記録は再判定できない（再判定すると不適合に戻る＝ラベルが変わる）
    last.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    assert replay.main(["--rejudge"]) == 1
    assert first.read_text(encoding="utf-8") == stale_text  # 途中までの書き込みを残さない
    assert capsys.readouterr().err  # 理由を標準エラーに出す
    last.write_text(json.dumps(json.loads((REPLAY_DIR / "sample_injection.json").read_text(encoding="utf-8")), ensure_ascii=False), encoding="utf-8")
    assert replay.main(["--rejudge"]) == 0
    assert replay.check(tmp_path) == []


# --- 画面に出る文の語（「原文」「本文」を使わない）---------------------------------------------------------------------------------
_SCREEN_MODULES = ("app/adjudicate.py", "app/agent/report.py", "app/checks/unverifiable_reason.py")


def _string_constants_outside_docstrings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    return [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


@pytest.mark.parametrize("rel", _SCREEN_MODULES)
def test_screen_sentences_never_say_honbun_or_genbun(rel):
    root = Path(__file__).resolve().parent.parent
    strings = _string_constants_outside_docstrings(root / rel)
    assert strings
    bad = [s for s in strings if "本文" in s or "原文" in s]
    assert bad == []  # 要項の文書は「要項」、提出物のページの文字は「提出物のページ」（コメント・docstring・内部の技術語は対象外）


def test_the_report_does_not_repeat_the_reason_label_before_a_fixed_gate_sentence():
    from app.agent.report import report_html
    from tests.factories import make_record

    quote = "参加を希望する方は、締切までに申し込んでください。"
    doc = make_doc("D1", quote + BLOCK_SEP + "別の文です。")
    req = make_verified("R1", doc=doc, needle=quote, kind=K.REQUIRED, check_class=C.CheckClass.NONE)
    (v,) = adjudicate(C.AdjudicationInput(requirements=(req,), docs=(doc.meta(),)))
    html = report_html(make_record(requirements=(req,), verdicts=(v,), docs=(doc.meta(),)))
    assert GATE_TEXT[HUMAN] in html
    assert C.REASON_LABEL_JA[HUMAN] + "：" not in html  # 見出しと固定文が重なって読めない
