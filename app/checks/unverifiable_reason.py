"""検査できないクラス（check_class=none）の要件に、確認不能の理由コードを割り当てる関門。

check_class=none の要件は、どの検査の観測も適用されず確認不能になる。その理由を全件「検査できる範囲の外」と言うと、利用者が
「何を自分で確認するのか」を読めない。ここで、引用（コードが要項から切り出した1文）の文面だけから、次のどれかを決める。

  HUMAN_ONLY   人が自分で確かめる条件（参加資格・本人の条件／登録・申込・提出の手続き／ダッシュボードなどの記入欄／費用の注意／任意の案内）
  FUTURE       提出後・期間中に守る約束、将来の時点の事項
  NOT_PUBLIC   非公開の情報（非公開のリポジトリ・社内の資料など）が要るため検査しない
  OUT_OF_SCOPE 上のどれにも当たらない（文の断片・総括・道具が検査していない提出物の中身）。迷ったら必ずこちら

方針:
  * 保守的に。確信できる一般の言い回しだけで割り当て、外れたら OUT_OF_SCOPE（＝この関門が無かった時と同じ挙動）。
    誤って HUMAN_ONLY などに倒すのは、OUT_OF_SCOPE に残すより悪い（利用者に間違った次の一手を示す）。
  * 入力は、引用の文字列と、コードが検証して持つ kind（コード側クロスチェック後の最終値）だけ。モデルの出力（check_class・slot・
    gist・自由文）は使わない。slot は Reader（モデル）が付けるだけで、コードが検証していないので、判断に使わない。
  * 純関数。判定のラベルは変えない（理由コードを選ぶだけ。判定を書けるのは adjudicate.py だけ）。
"""
import re
import unicodedata

from app.contracts import Kind, UnverifiableReason

# 文の終わり。これで終わらない引用は、文の断片（箇条書きの途中・切れた引用）として扱う
_SENTENCE_END = re.compile(r"(?:[。．.!?！？」』）)]|ください|いたします|お願いします|こと|です|ます|ません|ある|する)$")
_MIN_CHARS = 8  # これより短い引用は断片として扱う

# 意味が逆になりうる語（「登録不要」「ログイン登録なしで開ける」など）。手続き・記入欄・資格・費用・任意の割り当てを止める
_NEGATION = re.compile(r"不要(?:です|でし|だ|で[、。]|と(?:な|し)|[。、])|なしで|なしに|せずに|ずに|ことなく|ないで|必要ありません|必要はありません|いりません|要りません|不可|必須ではありません")
# 提出物そのものの公開状態・開けるか・審査員の見え方の話（auth_wall など、道具が検査する側の話題）。手続きと見ない
_PRODUCT_ACCESS = re.compile(r"審査員|審査委員|閲覧|アクセス|テストアカウント|認証情報|パスワード|ログイン(?:フォーム|画面|ページ)")

# --- FUTURE: 提出後・期間中の約束 ------------------------------------------------------------------
# 「応募期間中に提出」のような手続きの期限は含めない（期間中は／この期間／提出後／提出時点／までの間は だけ）
_FUTURE = re.compile(r"提出後|提出時点|期間中は|この期間|までの間は|審査期間中|締切後|締め切り後|発表(?:後|まで)|終了後")

# --- NOT_PUBLIC: 非公開の情報が要る ----------------------------------------------------------------
_NOT_PUBLIC = re.compile(
    r"(?:非公開|プライベート)(?:の|な)?(?:リポジトリ|資料|文書|ドキュメント|データ|ソースコード)|社内(?:の)?(?:資料|文書|ドキュメント|システム|ネットワーク)"
)
_NOT_PUBLIC_NEGATION = re.compile(r"ない|ず(?:に)?|いけ|避け|禁止|不可|ならな|除|以外|含め|公開して|公開さ")

# --- HUMAN_ONLY ---------------------------------------------------------------------------------
# 参加資格・本人の条件
_ELIGIBILITY = re.compile(
    r"\d+\s*歳\s*(?:以上|以下|未満|以内)|居住|在住|国籍|参加資格|応募資格|参加条件|応募条件|"
    r"(?:チーム|メンバー|参加者|人数)[^。]{0,12}?\d+\s*(?:名|人)\s*(?:まで|以内|以下|以上|未満)|"
    r"\d+\s*(?:名|人)\s*(?:まで|以内|以下|以上|未満)[^。]{0,8}(?:チーム|参加)"
)
# 登録・申込・提出の手続き（動詞の形まで見る）
_PROCEDURE = re.compile(
    r"(?:ご?登録|ご?申し?込み?|申込|エントリー|ご?応募)[^。]{0,15}(?:ください|必要|お願い|すること|しなければ|の上|いただ|までに)|"
    r"ご?提出(?:す(?:る|べき)?こと|しなければ|してください|ください|の上|をお願い)"
)
# ダッシュボード・フォーム・項目への記入（記入先の語と、記入の動詞の両方が要る）
_FIELD_PLACE = re.compile(r"ダッシュボード|フォーム|入力欄|記入欄|「[^」]{1,20}」項目|項目に|欄に|欄へ")
_FIELD_ACTION = re.compile(r"記入|記載|入力|登録|選択|添付|貼り付|貼付|チェック|作成|お知らせ|アップロード|提出")
# 費用・環境の注意
_COST = re.compile(r"課金|料金|費用|無料枠|有料|請求|従量|コスト|予算")


def _normalize(quote: str) -> str:
    return unicodedata.normalize("NFKC", quote).strip()


def _is_fragment(flat: str) -> bool:
    return len(flat) < _MIN_CHARS or _SENTENCE_END.search(flat) is None


def unverifiable_reason(quote: str, kind: Kind) -> UnverifiableReason:
    """check_class=none の要件の確認不能の理由コード。quote は VerifiedRequirement.span.original_span（コードが切り出した1文）。

    確信できる言い回しだけで HUMAN_ONLY／FUTURE／NOT_PUBLIC を返し、外れたら OUT_OF_SCOPE（迷ったらこちら）。
    """
    flat = _normalize(quote)
    if _is_fragment(flat):
        return UnverifiableReason.OUT_OF_SCOPE
    if _FUTURE.search(flat):
        return UnverifiableReason.FUTURE
    if _NOT_PUBLIC.search(flat) and not _NOT_PUBLIC_NEGATION.search(flat):
        return UnverifiableReason.NOT_PUBLIC
    if _NEGATION.search(flat):
        return UnverifiableReason.OUT_OF_SCOPE
    if _ELIGIBILITY.search(flat) or _COST.search(flat):
        return UnverifiableReason.HUMAN_ONLY
    if not _PRODUCT_ACCESS.search(flat):
        if _PROCEDURE.search(flat):
            return UnverifiableReason.HUMAN_ONLY
        if _FIELD_PLACE.search(flat) and _FIELD_ACTION.search(flat):
            return UnverifiableReason.HUMAN_ONLY
    if kind is Kind.OPTIONAL and "必須" not in flat:  # 任意の案内（kind は引用の語でコードが確かめた最終値）
        return UnverifiableReason.HUMAN_ONLY
    return UnverifiableReason.OUT_OF_SCOPE
