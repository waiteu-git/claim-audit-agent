"""検査の種類（check_class）が、要件の引用の内容と合っているかを、コードの語彙で確かめる関門。

check_class は Reader（モデル）が付ける。モデルが取り違えても、要項の注入文に狂わされても、無関係な要件に別の検査の合格
（例: 字数の要件に「Cloud Run署名あり」）が付いて「機械検証の適合」と見えてはならない。判定表（adjudicate）はこの関門を通った
要件にだけ、検査の観測を適用する。通らなければ「確認不能（検査できる範囲の外）」にする。

方針:
  * 検査を減らす・合格を付ける方向の誤りを塞ぐ関門なので、判定はコードの固定語彙だけで行う（モデルの出力は使わない）。
  * 語彙は広めに取る（普通の言い回しの要件を確認不能に落とさない）。狙うのは「引用がその検査の話題に全く触れていない」取り違え。
  * 引用は VerifiedRequirement.span.original_span（コードが原文から切り出した1文）。モデルの言い換え（gist）は使わない。
  * 語彙を足す時は tests/test_adversarial_adjudicate.py の「普通の言い回し」と「無関係な引用」の両方の表に例を足す。
"""
import re
import unicodedata

from app.contracts import CHECK_CLASS_CHECKER, CheckClass, Kind, VerifiedRequirement

_I = re.IGNORECASE

# 字数: 数値＋文字数の単位、または「字数」「文字数」等（上限の読み取り自体は text_length が引用から行う）
_LENGTH = re.compile(
    r"\d[\d,.]*\s*(?:文字|字|characters?|chars?|words?|語|ワード|単語)|字数|文字数|文字制限|"
    r"character\s+(?:limit|count)|word\s+(?:limit|count)|文字以内|字以内",
    _I,
)
# 誰が開けるか（認証・公開状態・アクセス）
_AUTH = re.compile(
    r"ログイン|ログオン|サインイン|認証|認可|アクセス|閲覧|公開|非公開|限定公開|審査員|審査委員|審査担当|審査者|審査用|審査期間|"
    r"アカウント|パスワード|権限|招待|制限|開け|見られ|見ることが|確認できる|誰でも|第三者|ブラウザ|デプロイ|ホスティング|サイト|ページ|\bIAM\b|"
    r"log\s*-?\s*in|logg?ing|sign\s*-?\s*in|\bauth|\baccess|public|private|reachable|available|\bopen\b|\bview|browse|credential|"
    r"password|account|permission|invite|restrict|judges?|reviewers?|\bdemo\b",
    _I,
)
# 実行環境（Cloud Run・Google Cloud・デプロイ先）
_RUNTIME = re.compile(
    r"cloud\s*run|google\s*cloud|\bgcp\b|run\.app|デプロイ|\bdeploy|ホスティング|\bhosting|稼働|動作|実行環境|サーバーレス|serverless|"
    r"コンテナ|\bcontainer|クラウド|\bcloud\b|インフラ|\bruntime\b|\bhost|サーバー|\bserver|実行|\brun\b|\brunning\b|\bruns\b|\bapp engine\b",
    _I,
)
# 漏洩（公開物に含めてはならないもの）
_LEAK = re.compile(
    r"漏洩|漏えい|流出|秘密|機密|極秘|キー|鍵|トークン|認証情報|資格情報|パスワード|個人情報|メール|アドレス|ソースコード|リポジトリ|"
    r"公開|掲載|記載|含め|含ま|載せ|出さ|晒|さらさ|ハードコード|内部|社内|非公開|"
    r"\bsecrets?\b|\bkeys?\b|\btokens?\b|credential|password|\bapi\b|e-?mail|\burls?\b|\bip\b|private|personal|\bpii\b|"
    r"leak|expos|disclos|includ|contain|hard-?cod|repositor|source\s*code|publi",
    _I,
)
# 案内・説明の記載（テストアカウント・使い方・手順）
_GUIDANCE = re.compile(
    r"テスト|アカウント|ログイン|認証|案内|手順|使い方|利用方法|利用手順|操作|説明|README|ドキュメント|ガイド|マニュアル|資格情報|パスワード|"
    r"審査員|動作確認|試し|方法|記載|明記|記述|含め|添え|"
    r"instruction|guide|account|credential|login|how\s+to|usage|document|manual|readme|judges?|try|steps?|\btest\b|demo",
    _I,
)
# URL・リンクの記載（動画・リポジトリ・デモ）
_URL = re.compile(
    r"URL|リンク|動画|ビデオ|ムービー|YouTube|Vimeo|デモ|リポジトリ|GitHub|GitLab|サイト|ページ|アドレス|スライド|資料|記事|"
    r"Zenn|Qiita|公開|提出|添付|掲載|記載|\blinks?\b|\bvideos?\b|\bdemo\b|repositor|\bsite\b|\bpage\b|\bslides?\b|\baddress\b|submit|include|provide",
    _I,
)

# 情報の置き場が、公開ページの本文ではなく、提出フォーム・ダッシュボードであることを示す語（「プロジェクトにご登録ください」
# 「項目にご記入ください」など）。公開ページの本文を調べる検査（contains_terms）は、こういう要件には当てられない:
# 本文に無いのは当然で、「無い」は不適合の証拠にならない（10/8 に自分のサービスを実 LP で自己監査して、動画URLの登録の要件が
# 「本文に無い」で不適合になった）。当てずに「検査できる範囲の外」（確認不能）にする＝誤った不適合を出さない側に倒す。
# 「項目」「欄」は、「『動作確認の方法』項目にご記載ください」のように記入先の欄を指す言い方を拾う（同日、Web版の作成が難しい
# 場合の事情を欄に書く要件が、gemini-3.5-flash の自己監査で「本文に無い」不適合になった）。「次の項目を記載すること」のような
# 一覧の意味の「項目」も確認不能に倒れるが、誤った不適合を出すよりよい。
_ELSEWHERE = re.compile(
    r"登録|記入|入力|フォーム|ダッシュボード|申し込|申込|届け出|申請|項目|欄|"
    r"\bregist|\bform\b|dashboard|\benter\b|\bfill\b|\bapply\b|\bapplication\b|\bfield\b",
    _I,
)
_PAGE_TEXT_CLASSES = frozenset({CheckClass.GUIDANCE_PRESENT, CheckClass.URL_PRESENT})

_VOCAB: dict[CheckClass, re.Pattern[str]] = {
    CheckClass.LENGTH_LIMIT: _LENGTH,
    CheckClass.AUTH_WALL: _AUTH,
    CheckClass.RUNTIME_SIGNATURE: _RUNTIME,
    CheckClass.LEAK: _LEAK,
    CheckClass.GUIDANCE_PRESENT: _GUIDANCE,
    CheckClass.URL_PRESENT: _URL,
}


def quote_supports_class(check_class: CheckClass, quote: str) -> bool:
    """引用（コードが原文から切り出した1文）が、この検査の話題に触れているか。NONE（検査できない）は常に False。

    NFKC に畳んでから照合する（全角英数・全角空白で語彙をすり抜けさせない）。
    """
    pattern = _VOCAB.get(check_class)
    if pattern is None:
        return False
    text = unicodedata.normalize("NFKC", quote)
    if check_class in _PAGE_TEXT_CLASSES and _ELSEWHERE.search(text) is not None:
        return False  # 置き場が提出フォームなどで、公開ページの本文には無い（上の _ELSEWHERE の注）
    return pattern.search(text) is not None


def is_checkable_requirement(req: VerifiedRequirement) -> bool:
    """検査の種類があり、検証済みの引用がその話題に触れている要件か。推測・引用なし・検査できないクラスは False。

    RunState.is_checkable（Governor の許可）と AUTORUN の計画が、同じ関数で「検査できる」を決める（同じ事実を2か所で判定しない）。
    """
    if req.kind is Kind.SPECULATIVE or req.span is None:
        return False
    if CHECK_CLASS_CHECKER[req.check_class] is None:
        return False
    return quote_supports_class(req.check_class, req.span.original_span)
