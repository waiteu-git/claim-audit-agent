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

from app.contracts import CheckClass

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
    return pattern.search(unicodedata.normalize("NFKC", quote)) is not None
