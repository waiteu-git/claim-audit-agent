"""contains_terms: 提出物の可視テキストに、要件が求める語（テストアカウントの案内・動画URL など）があるかを調べる（設計 §3・§4）。

取り決め（判定表 adjudicate.py が前提にしている形）:
  * 語は check_class（guidance_present／url_present）ごとの固定辞書（このファイルのコード定数）。LLM もリクエスト（要件の文章）も
    語を決めない。見るのは可視テキスト（SanitizedDoc.visible_text）だけで、HTML コメント・隠しテキスト・属性の中の語は
    洗浄で可視テキストから分離されているので命中にならない。
  * 見つかった時: checker=CONTAINS_TERMS・code=TERMS_FOUND・outcome=PASS・strong=False（語が在る証明であって内容の保証ではない）。
  * 無い時: code=TERMS_ABSENT・outcome=INCONCLUSIVE。不適合にするかは判定表が、文書の完全性
    （truncated=false・page_class=content）と要件の kind（必須）で決める。チェッカーは決めない。
  * doc_id は必ず付ける（判定表が文書の完全性を引く）。
  * 注入疑いの区間（本文の INJECTION_PLACEHOLDER、または洗浄が記録した可視の検知区間）は命中に数えない
    （偽の命令の中に「テストアカウント」と書いて、案内があるように見せかけられないため）。そういう文書では TERMS_ABSENT を
    結論にしない（置き換えた区間に語があったかもしれない）。不確定（code=ERROR・outcome=INCONCLUSIVE・facts reason=masked_text）
    で返す。TERMS_FOUND は区間の外で見つかれば有効。
  * 判定表は、提出物（role=submission）の文書の観測だけを採り、「禁止」の要件にはこの検査を当てない（向きが逆）。

命中の規則:
  * 文（ブロック境界・改行・句点・感嘆符・疑問符・「. 」で区切る）ごとに調べる。比較は NFKC に畳み大文字小文字を畳んでから行う
    （全角半角・大小の表記ゆれを吸収する）。
  * guidance_present は「テスト用アカウント」「デモ用ID」「test account」「使い方」「how to use」のように、案内の名詞が在る文。
    ただし同じ文に否定・先送りの言い回し（「用意していません」「後日お知らせ」「no test account」）があれば、
    言及だけで案内ではないので命中にしない。「アカウント」「ログイン」だけの文は命中にしない。
  * url_present は、可視テキストにある http(s) の URL のうち、ホストが動画・スライド・コード置き場・記事の共有サービス（固定の一覧）のもの。
    リンクは、アンカーの文言が可視テキストに現れているものだけを見る（隠し要素のリンクを命中にしない）。ルートだけの URL は数えない。
facts は種類ごとの件数だけ（見つけた文字列そのものは載せない）。
"""
import re
import unicodedata
from collections.abc import Iterator
from urllib.parse import urlsplit

from app.contracts import (
    BLOCK_SEP,
    INJECTION_PLACEHOLDER,
    CheckClass,
    Checker,
    Observation,
    ObsCode,
    ObsOutcome,
    SanitizedDoc,
    ToolName,
    VerifiedRequirement,
)

_SEP = r"[\s・_\-]*"

# ---- guidance_present の辞書（NFKC・casefold 後の文字列に当てる）------------------------------------
_ACCOUNT_QUALIFIER_JA = r"(?:テスト|試験|検証|デモ|サンプル|ゲスト|お試し|審査員?|ジャッジ|レビュ(?:ー|アー)?)(?:用|向け|専用)?(?:の)?"
_ACCOUNT_NOUN_JA = r"(?:アカウント|ユーザー?(?:名)?|id|ログイン(?:情報|id)?|パスワード|認証情報)(?![a-z0-9])"
_ACCOUNT_QUALIFIER_EN = r"(?:test|testing|demo|trial|sample|guest|reviewer|judge|judges|evaluator)"
_ACCOUNT_NOUN_EN = r"(?:accounts?|users?|logins?|credentials?|passwords?|ids?)\b"
_CREDENTIAL_PAIR = (
    r"(?:id|user(?:name)?|ユーザー?名|ログインid)\s*[:=]\s*\S+[\s/,、]*(?:pw|pass(?:word)?|パスワード)\s*[:=]\s*\S+"
)

GUIDANCE_TERMS: dict[str, re.Pattern[str]] = {
    "account": re.compile(
        "|".join(
            (
                _ACCOUNT_QUALIFIER_JA + _ACCOUNT_NOUN_JA,
                r"(?<![a-z])" + _ACCOUNT_QUALIFIER_EN + _SEP + _ACCOUNT_NOUN_EN,
                _CREDENTIAL_PAIR,
            )
        )
    ),
    "usage": re.compile(
        "|".join(
            (
                r"使い方|使用方法|利用方法|ご利用方法|操作方法|操作手順|利用手順|利用ガイド|ご利用ガイド|ご利用の流れ|始め方|はじめかた|チュートリアル"
                r"|ユーザーガイド|クイックスタート",
                r"\bhow to (?:use|log ?in|sign ?in|try|get started)\b|\buser guide\b|\busage guide\b|\bgetting started\b"
                r"|\bquick ?start\b|\btutorial\b|\bwalk-?through\b|\bstep[- ]by[- ]step\b|\b(?:setup|usage) instructions\b",
            )
        )
    ),
}
# 言及だけで案内ではない文（否定・先送り）。generic な「ない」は含めない（「お持ちでない場合は、テスト用アカウントをご利用ください」は案内）
_NOT_GUIDANCE = re.compile(
    r"ありません|ございません|用意(?:して)?(?:い)?(?:ません|できません)|提供(?:して)?(?:い)?(?:ません|できません)|設けて(?:い)?ません"
    r"|準備中|後日|追って|近日|予定|未定|未実装|不要|(?:なし|無し)(?:で|でも)"
    r"|\b(?:no|not|none|n/a|without|unavailable|tbd|todo)\b|coming soon|isn't|aren't|don't|doesn't|won't|cannot|can't"
    r"|will be (?:announced|provided|shared)|to be (?:announced|provided|shared)"
)

# ---- url_present の辞書 -----------------------------------------------------------------------------
URL_HOSTS: dict[str, tuple[str, ...]] = {
    "video": (
        "youtube.com",
        "youtu.be",
        "vimeo.com",
        "nicovideo.jp",
        "nico.ms",
        "loom.com",
        "dailymotion.com",
        "bilibili.com",
        "twitch.tv",
        "streamable.com",
        "tiktok.com",
    ),
    "slides": ("speakerdeck.com", "slideshare.net"),
    "repo": ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org"),
    "article": ("zenn.dev", "qiita.com", "note.com"),
}
_URL = re.compile(r"https?://[^\s<>\"'「」『』（）()、。]+")
_URL_TRAIL = ".,;:!?)]}>'\"」』）"

_SENTENCE_SPLIT = re.compile(f"[{BLOCK_SEP}\\n。！？!?]|\\.(?=\\s)")


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _masked_text(doc: SanitizedDoc) -> tuple[str, bool]:
    """検知区間を INJECTION_PLACEHOLDER に置き換えた可視テキストと、置き換え（または元からの置換記号）があったか。"""
    text = doc.visible_text
    spans = sorted(
        (s.start, s.end) for s in doc.injection_signals if s.visible and s.start is not None and s.end is not None
    )
    out: list[str] = []
    pos = 0
    for a, b in spans:
        if a < pos:
            pos = max(pos, b)
            continue
        out.append(text[pos:a])
        out.append(INJECTION_PLACEHOLDER)
        pos = b
    out.append(text[pos:])
    masked = "".join(out)
    return masked, INJECTION_PLACEHOLDER in masked


def _sentences(text: str) -> Iterator[str]:
    for s in _SENTENCE_SPLIT.split(text):
        s = s.strip()
        if s:
            yield s


def _guidance_hits(text: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    for sentence in _sentences(text):
        folded = _fold(sentence)
        if _NOT_GUIDANCE.search(folded):
            continue
        for kind, pat in GUIDANCE_TERMS.items():
            if pat.search(folded):
                hits[kind] = hits.get(kind, 0) + 1
    return hits


def _host_kind(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for kind, names in URL_HOSTS.items():
        if any(host == n or host.endswith("." + n) for n in names):
            return kind
    return None


def _url_kind(raw: str) -> str | None:
    try:
        parts = urlsplit(raw.rstrip(_URL_TRAIL))
        host = parts.hostname or ""
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    if not parts.path.strip("/") and not parts.query:
        return None  # サービスのトップだけ。個別の動画・資料を指していない
    return _host_kind(host)


def _url_hits(doc: SanitizedDoc, text: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    seen: set[str] = set()
    for m in _URL.finditer(unicodedata.normalize("NFKC", text)):
        kind = _url_kind(m.group(0))
        if kind is not None and m.group(0) not in seen:
            seen.add(m.group(0))
            hits[kind] = hits.get(kind, 0) + 1
    folded_text = _fold(text)
    for lk in doc.links:  # 可視のアンカーのリンクだけ（アンカー文言が可視テキストに現れないものは隠し要素かもしれない）
        anchor = _fold(lk.anchor_text).strip()
        if not anchor or lk.href in seen or anchor not in folded_text:
            continue
        kind = _url_kind(lk.href)
        if kind is not None:
            seen.add(lk.href)
            hits[kind] = hits.get(kind, 0) + 1
    return hits


def _obs(req: VerifiedRequirement, obs_id: str, code: ObsCode, outcome: ObsOutcome, doc: SanitizedDoc, facts: dict) -> Observation:
    return Observation(
        obs_id=obs_id,
        tool=ToolName.RUN_CHECK,
        checker=Checker.CONTAINS_TERMS,
        req_id=req.req_id,
        doc_id=doc.doc_id,
        code=code,
        outcome=outcome,
        strong=False,
        facts=facts,
    )


def check_contains_terms(req: VerifiedRequirement, doc: SanitizedDoc, obs_id: str) -> Observation:
    if req.check_class not in (CheckClass.GUIDANCE_PRESENT, CheckClass.URL_PRESENT):
        return _obs(req, obs_id, ObsCode.NO_PARAMETER, ObsOutcome.INCONCLUSIVE, doc, {"reason": "no_terms_for_class"})
    text, masked = _masked_text(doc)
    hits = _guidance_hits(text) if req.check_class is CheckClass.GUIDANCE_PRESENT else _url_hits(doc, text)
    if hits:
        facts: dict = {k: min(n, 99) for k, n in sorted(hits.items())}
        facts["hits"] = min(sum(hits.values()), 999)
        if masked:
            facts["masked"] = True  # 置き換えた区間の外で見つかった（有効）。区間の中は見ていない
        return _obs(req, obs_id, ObsCode.TERMS_FOUND, ObsOutcome.PASS, doc, facts)
    if masked:
        return _obs(req, obs_id, ObsCode.ERROR, ObsOutcome.INCONCLUSIVE, doc, {"reason": "masked_text"})
    return _obs(req, obs_id, ObsCode.TERMS_ABSENT, ObsOutcome.INCONCLUSIVE, doc, {"chars": min(len(doc.visible_text), 999999)})
