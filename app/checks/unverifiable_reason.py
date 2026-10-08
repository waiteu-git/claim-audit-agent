"""検査できないクラス（check_class=none）の要件に、確認不能の理由コードを割り当てる関門。

check_class=none の要件は、どの検査の観測も適用されず確認不能になる。その理由を全件「検査できる範囲の外」と言うと、利用者が
「何を自分で確認するのか」を読めない。ここで、引用（コードが要項から切り出した1文）の文面だけから、次のどれかを決める。

  HUMAN_ONLY   人が自分で確かめる条件（参加資格・本人の条件／登録・申込・提出の手続き／ダッシュボードなどの記入欄／費用の注意／任意の案内）
  FUTURE       提出後・期間中に守る約束（提出より後であることが明示され、守る動作が同じ文にあるものだけ）
  NOT_PUBLIC   非公開の情報（非公開のリポジトリ・社内の資料など）が要る／求められるため検査しない
  OUT_OF_SCOPE 上のどれにも当たらない（文の断片・総括・道具が検査していない提出物の中身）。迷ったら必ずこちら

方針（保守的に）:
  * 誤って HUMAN_ONLY などに倒すのは、OUT_OF_SCOPE に残すより悪い（利用者に間違った次の一手を示す）。だから段構えにする:
      1. 文として読めない引用（断片・途中で切れた引用）は、語があっても割り当てない。
      2. 否定・不要・不問・許可・運営側の言い切り（〜します）は、手続き・資格・費用・約束の語があっても割り当てない
         （「登録は必要ありません」「提出後でも構いません」は、語があっても意味が逆・条件ではない）。
      3. その上で、確信できる言い回しだけを通す。裸のキーワード（登録・費用・居住・提出後…）だけでは割り当てず、
         「誰に何を求める文か」が分かる形（名詞＋依頼・義務の動詞、記入先＋記入の依頼、時点＋守る動作…）を要る。
      4. 提出物の機能・中身を述べる文（実装・画面・ユーザー…）と、審査員の見え方の話（検査する側）は割り当てない。
  * 入力は、引用の文字列と、コードが検証して持つ kind（コード側クロスチェック後の最終値）だけ。モデルの出力（check_class・slot・
    declared_kind・chips・gist・Planner の確認不能の印）は使わない。tests/test_unverifiable_reason.py が、これらを振っても結果が変わらないことと、
    kind が結果を変えるのが次の2つだけであることを固定する: 任意の案内（kind=任意でも、文に任意・自由の言い回しが要る）と、
    禁止の要件に「非公開の情報が要る」と言わないこと。
  * 純関数。判定のラベルは変えない（理由コードを選ぶだけ。判定を書けるのは adjudicate.py だけ）。
  * 「3つの同梱記録にだけ効く固有の語」は入れない。語は、一般の要項に出る言い回しで選ぶ。
"""
import re
import unicodedata

from app.contracts import Kind, UnverifiableReason

# --- 1. 文として読めるか ---------------------------------------------------------------------------------------
_SENTENCE_END = re.compile(r"(?:[。．.!?！？」』）)]|ください|こと|です|ます|ません|ある)$")
_ELLIPSIS_END = re.compile(r"\.\.\.$")  # 80字で切った引用（「…」は NFKC で「...」になる）は、文の前半だけ
_MIN_CHARS = 8  # これより短い引用は断片として扱う

# --- 2. 最初に OUT_OF_SCOPE へ落とす（意味が逆・条件ではない）文 --------------------------------------------------------
# 不要・必要なし・不問・費用なし（「登録は必要ありません」「国籍は問いません」「費用はかかりません」）。「不要なリソース」の形容は含めない
_EXEMPT = re.compile(
    r"不要(?![なのに])|"
    r"必要(?:が|は|も|では|じゃ)?(?:あり|ござい)?(?:ませ|ない|なし|なく)|必要とし(?:ませ|ない)|必要とせ|"
    r"なくても|なくてよ|"
    r"問(?:いませ|わな|わず)|不問|"
    r"かかりませ|かからな|発生しませ|発生しな|生じませ|生じな|求めませ|求めな|課しませ|課さな|いりませ|要りませ"
)
# 許可・容認（「提出後でも構いません」「修正が認められる」）
_PERMISSION = re.compile(
    r"構いません|かまいません|構わない|差し支え|問題ありません|問題ない|認められ|認めま|認めて|許可|許され|許容|可とします|"
    r"でもよい|てもよい|ても結構|でも結構|結構です"
)
# 運営側の言い切り（「結果を公開します」「連絡します」）。参加者への依頼ではない。「お願いいたします」は依頼なので先に除く
_REQUEST_IDIOM = re.compile(r"お願い(?:いた)?します")
_OPERATOR = re.compile(r"し(?:ます|ました)(?:。|$)|差し上げます")
# 末尾が平叙の否定（「〜ません。」「〜ない。」）。「〜ないでください」など依頼の否定（ください終わり）は含まない。
# 「提出しなければなりません」は義務なので、先に「すること」に置き換えてから見る
_OBLIGATION = re.compile(r"(?:なければ|なくては)(?:ならない|なりません|いけない|いけません)")
_NEG_END = re.compile(r"(?:ません|ない|なし)[。．]?$")
# 提出物の機能・中身・画面を述べる文（道具が検査していない提出物の中身）
_PRODUCT = re.compile(
    r"実装|機能[をがはのにで]|アプリ内|アプリの|画面|システム内|ユーザー|利用者|データベース|"
    r"(?<![A-Za-z])(?:API|UI|UX)(?![A-Za-z])|サーバー|フロントエンド|バックエンド|"
    r"README|ドキュメント|設計|アーキテクチャ|ソースコード|デザイン|ブラウザ|"
    r"表示(?:する|させ|されること|できる)|出力|検証する|処理|フレームワーク|ライブラリ|モック",
    re.IGNORECASE,
)
# 提出物そのものの公開状態・開けるか・審査員の見え方の話（auth_wall など、道具が検査する側の話題）。手続きと見ない
_PRODUCT_ACCESS = re.compile(r"審査員|審査委員|閲覧|アクセス|テストアカウント|認証情報|パスワード|ログイン(?:フォーム|ページ)")

# --- FUTURE: 提出後・期間中に守る約束 --------------------------------------------------------------------------------------
# 「提出より後」であることの明示（提出後・審査期間・発表まで…）。裸の「この期間」「提出時点」「終了後」は含めない
_FUTURE_ANCHOR = re.compile(
    r"提出(?:後|完了後|以降)|審査期間|審査中|期間中は|までの間は|審査(?:の終了)?(?:後|まで)|発表(?:後|まで)|受賞後"
)
# 守る動作（変更・修正・削除をしない／ご遠慮／保つ・維持）。時点の明示と、同じ文に両方あるときだけ FUTURE
_PROMISE = re.compile(
    r"(?:変更|修正|編集|更新|削除|解除|停止|閉鎖|改変)(?:を加え|を行わ|をし|し)ない(?:でください|よう|こと)|"
    r"(?:変更|修正|編集|更新|削除|解除|停止|閉鎖|改変)[をは]?(?:し|行っ|加え)?て(?:はならな|はいけな|はなりませ|はいけませ)|"
    r"ご遠慮|お控え|"
    r"保っ|保ち|保つ|維持|公開(?:状態)?を継続|公開し続け"
)

# --- NOT_PUBLIC: 非公開の情報が要る／求められる ------------------------------------------------------------------------------
_PRIVATE = re.compile(
    r"(?:非公開|限定公開|プライベート|private)[のな]?(?:リポジトリ|資料|文書|ドキュメント|ソースコード)|"
    r"社内の?(?:資料|文書|ドキュメント|システム|ネットワーク)|内部の?(?:資料|文書|ドキュメント)",
    re.IGNORECASE,
)
# 審査する側がそれを見る／それに基づく、という向き（権限・招待・共有・提供・基づく…）
_PRIVATE_NEEDED = re.compile(r"閲覧権限|アクセス権|権限を(?:付与|与え)|招待|共有|提供|開示|提示|参照|基づ|もとに|元に|用い|利用して|使用して")
# 禁止・対象外・失格・許可・否定は、「要る」の向きではない
_NOT_PUBLIC_BLOCK = re.compile(r"ない|ず(?:に)?|いけ|避け|禁止|不可|なりませ|できませ|失格|対象外|除|以外|構い|問い|不要")

# --- HUMAN_ONLY ---------------------------------------------------------------------------------------------------------
# 参加資格・本人の条件（参加する側が主語の形）
_AGE = re.compile(r"\d+\s*歳\s*(?:以上|以下|未満|以内)")
_PARTICIPANT = re.compile(r"方|者|個人|チーム|メンバー|学生|生徒|社会人|法人|団体|企業")
_RESIDENCE = re.compile(r"(?:居住|在住)(?:する|している|の)[^。]{0,16}?(?:方|者|チーム|人)")
_TEAM_SIZE = re.compile(
    r"(?:チーム|メンバー|参加者|人数)[^。]{0,12}?(?:\d+\s*[名人]\s*(?:まで|以内|以下|以上|未満|から\s*\d+\s*[名人])|最大\s*\d+\s*[名人])|"
    r"\d+\s*[名人]\s*(?:まで|以内|以下|以上|未満)[^。]{0,8}(?:チーム|参加)"
)
_STATUS = re.compile(
    r"(?:参加者|応募者|申請者|代表者)[はが][^。]{0,24}?(?:であること|に限|でなければ)|[のな][方者](?:に限[りる]|のみ|が対象|を対象)"
)
# 費用・環境の注意（利用者の支払い・削除・上限に関する述語を伴うもの）
_COST_WORD = re.compile(r"課金|料金|費用|請求|無料枠|有料")
_COST_PREDICATE = re.compile(r"発生|かか[りる]|負担|され|超え|超過|削除|停止|注意|アップグレード|必要")
# 登録・申込・提出の手続き（名詞の直後に、依頼・義務の動詞が来る形。「登録機能」「応募作品」「ご提出いただいた」「ご提出いただくプロジェクトは」
# のような名詞・過去・連体の形は含めない）
_PROCEDURE = re.compile(
    r"(?:登録|申し?込|エントリー|応募|提出)[をも]?"
    r"(?:お願い|ください|してください|んでください|が必要|は必要|しなければ|しなくては|する必要|すること|の上|のうえ|を完了)"
)
# ダッシュボード・フォーム・項目への記入（記入先の語の後ろに、依頼の形の動詞が要る。記入先の語と動詞は別の文字列）
_FIELD = re.compile(
    r"(?:ダッシュボード|フォーム|入力欄|記入欄|「[^」]{1,20}」(?:項目|欄))[^。]{0,60}?"
    r"(?:ご?(?:記入|記載|入力|選択|添付|回答|送信)(?:の上|のうえ|ください|をお願い)|"
    r"(?:記入|記載|入力|選択|添付|回答|送信)してください|"
    r"お知らせください|(?:アップロードして|貼り付けて)ください)"
)
# 任意の案内: kind=任意（コードが確かめた最終値）に加えて、文にも任意・自由の言い回しが要る。提出物の中身を指す語があれば除く
_OPTIONAL_CUE = re.compile(r"任意|お気軽|自由に|どうぞ|歓迎|可能です|できます|ご希望|希望する|おすすめ|お勧め")
# 提出物の中身を指す語（_PRODUCT・_PRODUCT_ACCESS に無いもの。この2つは任意の案内の判定より前に効く）
_OPTIONAL_CONTENT = re.compile(
    r"字数|文字|文章|説明|公開|ログイン|認証|推奨環境|リポジトリ|ソース|テスト|加点|評価|デプロイ|言語|サイト|URL|スライド|ライセンス|コード",
    re.IGNORECASE,
)


def _normalize(quote: str) -> str:
    return unicodedata.normalize("NFKC", quote).strip()


def _is_fragment(flat: str) -> bool:
    return len(flat) < _MIN_CHARS or _ELLIPSIS_END.search(flat) is not None or _SENTENCE_END.search(flat) is None


def _is_operator_statement(flat: str) -> bool:
    return _OPERATOR.search(_REQUEST_IDIOM.sub("", flat)) is not None


def _is_future(flat: str) -> bool:
    return _FUTURE_ANCHOR.search(flat) is not None and _PROMISE.search(flat) is not None


def _is_not_public(flat: str) -> bool:
    return _PRIVATE.search(flat) is not None and _PRIVATE_NEEDED.search(flat) is not None and _NOT_PUBLIC_BLOCK.search(flat) is None


def _is_eligibility(flat: str) -> bool:
    return (
        (_AGE.search(flat) is not None and _PARTICIPANT.search(flat) is not None)
        or _RESIDENCE.search(flat) is not None
        or _TEAM_SIZE.search(flat) is not None
        or _STATUS.search(flat) is not None
    )


def _is_cost_notice(flat: str) -> bool:
    return _COST_WORD.search(flat) is not None and _COST_PREDICATE.search(flat) is not None


def _is_optional_guidance(flat: str, kind: Kind) -> bool:
    return (
        kind is Kind.OPTIONAL
        and "必須" not in flat
        and _OPTIONAL_CUE.search(flat) is not None
        and _OPTIONAL_CONTENT.search(flat) is None
    )


def unverifiable_reason(quote: str, kind: Kind) -> UnverifiableReason:
    """check_class=none の要件の確認不能の理由コード。quote は VerifiedRequirement.span.original_span（コードが切り出した1文）。

    確信できる言い回しだけで HUMAN_ONLY／FUTURE／NOT_PUBLIC を返し、外れたら OUT_OF_SCOPE（迷ったらこちら）。
    """
    flat = _normalize(quote)
    if _is_fragment(flat):
        return UnverifiableReason.OUT_OF_SCOPE
    if _EXEMPT.search(flat) or _PERMISSION.search(flat) or _is_operator_statement(flat):
        return UnverifiableReason.OUT_OF_SCOPE
    if _is_future(flat):
        return UnverifiableReason.FUTURE
    if kind is not Kind.PROHIBITED and _is_not_public(flat):  # 禁止の向きの要件に「非公開の情報が要る」とは言わない
        return UnverifiableReason.NOT_PUBLIC
    if _NEG_END.search(_OBLIGATION.sub("すること", flat)) or _PRODUCT.search(flat) or _PRODUCT_ACCESS.search(flat):
        return UnverifiableReason.OUT_OF_SCOPE
    if (
        _is_eligibility(flat)
        or _is_cost_notice(flat)
        or _PROCEDURE.search(flat) is not None
        or _FIELD.search(flat) is not None
        or _is_optional_guidance(flat, kind)
    ):
        return UnverifiableReason.HUMAN_ONLY
    return UnverifiableReason.OUT_OF_SCOPE
