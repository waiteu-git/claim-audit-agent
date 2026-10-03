"""text_length: 提出物の本文の字数を数え、要項の上限に照らす（設計 §3 判定表の注・§4 run_check）。

字数の数え方は原文に定義されていないことが多いので、設計どおり「空白除去あり／なし」の両方で数える。
  * 両方が上限を超える      → OVER_LIMIT（不適合・強）
  * 両方が上限以内           → WITHIN_LIMIT（適合・強）
  * 片方だけが超える         → LIMIT_UNDECIDABLE（確認不能。数え方を決めるのは人）
さらに絵文字・結合文字の数え方（書記素・コードポイント・UTF-16 の単位）でも結論が割れないことを要求する:
最小に数える流儀（空白なし・書記素）でも超えるなら不適合、最大に数える流儀（空白あり・UTF-16）でも収まるなら適合、
それ以外は確認不能。ふつうの日本語・英数の本文では、これは「空白あり／なし」の2通りと同じ結論になる。

数える単位:
  chars_with_ws / chars_no_ws … NFC に正規化したコードポイント数。空白は str.isspace()（全角空白・NBSP・改行を含む）。
      改行は \\r\\n・\\r を \\n 1つにそろえ、サニタイザが入れたブロック境界（U+001E）の連続は改行1つとして数える。前後の空白は数えない。
  units_min … 空白なしの書記素（結合文字・異体字セレクタ・ZWJ 連結・国旗の対・半角カナの濁点を前の文字に含める）の数。
  units_max … 空白ありの UTF-16 コード単位数（JavaScript の length 相当。絵文字は2）。

上限（パラメータ）は引数で受けず、検証済み引用（VerifiedRequirement.span.original_span）の中に実在する数値だけを使う
（設計 §4 run_check）。「以内・以下・まで」は上限、「未満」は上限−1、「以上」は下限（このチェッカーは上限だけを見る）、
「程度・前後」は目安、上限の数値が複数あって区別できない時は決めない（NO_PARAMETER）。

限界: 渡された文書の可視テキスト全体を数える。見出し・ナビゲーション・フッタも含むので、説明文だけのページ
（または説明文が主体のページ）を対象に選ぶのは呼び出し側（AUTORUN／Planner）の責務。

敵対レビューで足した、上限の読み取りの防御（上限を取り違えると、無関係な上限で「不適合」と言い切ってしまう）:
  * タイトル・名称・コメントなど、短い欄の上限は、提出物の本文全体の上限ではない（reason=other_subject）。説明を指す語が一緒にあれば読む。
  * 同じ文に別の単位（語・words・行・バイト）の上限があれば、文字数の上限と決められない（reason=other_unit）。
  * 「全角800字」は半角を0.5字、「半角1,000文字」は全角を2字として数える（basis）。「全角・半角を問わず」「全角と半角の両方の数字」は従来どおり。
  * 注入疑いの置換記号（INJECTION_PLACEHOLDER）が本文にあれば、数えた字数は本当の字数の下限でしかない（置換で縮んでいる）。
    超過（不適合）は下限でも成り立つが、「上限以内」は言えない（長い本文を注入文に見せかけて縮め、字数制限をすり抜ける回避を塞ぐ）。
"""
import re
import unicodedata
from dataclasses import dataclass

from app.contracts import (
    BLOCK_SEP,
    INJECTION_PLACEHOLDER,
    Checker,
    Observation,
    ObsCode,
    ObsOutcome,
    SanitizedDoc,
    ToolName,
    VerifiedRequirement,
)

_MAX_LIMIT = 1_000_000

# --- 字数を数える -----------------------------------------------------------------------------
_BLOCK_RUN = re.compile(f"{re.escape(BLOCK_SEP)}+")


@dataclass(frozen=True)
class CharCounts:
    chars_with_ws: int
    chars_no_ws: int
    units_min: int
    units_max: int
    fw_min2: int = 0  # 全角基準の最小: 空白なしの書記素ごとに 全角=2・それ以外=1（半角2字=全角1字。上限と比べる時は上限の2倍）
    hw_max: int = 0  # 半角基準の最大: 空白を含む全文字ごとに 全角・曖昧幅=2・それ以外=1（全角1字=半角2字）


def _normalize(text: str) -> str:
    t = unicodedata.normalize("NFC", text)
    t = _BLOCK_RUN.sub("\n", t)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    return t.strip()


def _is_extender(ch: str) -> bool:
    """直前の文字と1文字に数える結合・修飾の文字。"""
    cp = ord(ch)
    if unicodedata.category(ch) in ("Mn", "Me", "Mc"):
        return True
    return (
        cp == 0x200D  # ZWJ
        or 0xFE00 <= cp <= 0xFE0F  # 異体字セレクタ
        or 0x1F3FB <= cp <= 0x1F3FF  # 肌の色の修飾
        or 0xE0020 <= cp <= 0xE007F  # タグ文字（国旗の地域指定など）
        or cp in (0xFF9E, 0xFF9F)  # 半角カナの濁点・半濁点
    )


def _is_regional_indicator(ch: str) -> bool:
    return 0x1F1E6 <= ord(ch) <= 0x1F1FF


def _graphemes(text: str):
    """書記素（見た目の1文字）の近似。各書記素の先頭の文字を返す。外部ライブラリを使わず、日本語の本文で結論が割れる主な形だけを扱う。"""
    started = False
    joined = False  # 直前が ZWJ なら次の1文字も同じ書記素
    ri_open = False  # 国旗（地域指示子2つで1文字）の前半を数えた直後
    for ch in text:
        if ord(ch) == 0x200D:
            joined = True
            continue
        if joined:
            joined = False
            continue
        if _is_regional_indicator(ch):
            if ri_open:
                ri_open = False
                continue
            ri_open = True
            started = True
            yield ch
            continue
        ri_open = False
        if _is_extender(ch) and started:
            continue
        started = True
        yield ch


def grapheme_count(text: str) -> int:
    """書記素（見た目の1文字）の近似数。"""
    return sum(1 for _ in _graphemes(text))


def _is_wide(ch: str) -> bool:
    return unicodedata.east_asian_width(ch) in ("W", "F")


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2  # 孤立サロゲートでも落とさない（1単位と数える）


def count_chars(text: str) -> CharCounts:
    t = _normalize(text)
    no_ws = "".join(ch for ch in t if not ch.isspace())
    graphemes = list(_graphemes(no_ws))
    return CharCounts(
        chars_with_ws=len(t),
        chars_no_ws=len(no_ws),
        units_min=len(graphemes),
        units_max=utf16_len(t),
        fw_min2=sum(2 if _is_wide(g) else 1 for g in graphemes),
        hw_max=sum(2 if unicodedata.east_asian_width(ch) in ("W", "F", "A") else 1 for ch in t),
    )


# --- 要項の引用から上限を取り出す --------------------------------------------------------------
_NUM = r"(\d{1,3}(?:,\d{3})+|\d+)"
_UNIT = r"(?:文字|字|characters?|chars?)"
_AFTER = 24  # 数値＋単位の後ろ何字までに方向語（以内・以上…）を探すか
_GAP = r"^[\s)）」』】]*(?:[（(][^）)]{0,12}[）)])?\s*"  # 閉じ括弧・「（空白を含む）」のような注記を読み飛ばす
_UPPER_POST = re.compile(_GAP + r"(?:以内|以下|まで|未満|を超え(?:ない|ず)|を越え(?:ない|ず)|(?:or|and)\s+(?:less|fewer|under))", re.I)
_LOWER_POST = re.compile(_GAP + r"(?:以上|を超える|を越える|から|(?:or|and)\s+(?:more|over))", re.I)
_APPROX_POST = re.compile(_GAP + r"(?:程度|前後|くらい|ぐらい|目安)")
_STRICT_POST = re.compile(_GAP + r"未満")
_UPPER_PRE = re.compile(r"(?:上限|最大|多くとも|at\s+most|up\s+to|maximum|max\.?|within|no\s+more\s+than|less\s+than|fewer\s+than|under)\s*[:：はで]?\s*$", re.I)
_LOWER_PRE = re.compile(r"(?:最低|最小|少なくとも|at\s+least|minimum|min\.?|more\s+than|over)\s*[:：はで]?\s*$", re.I)
_STRICT_PRE = re.compile(r"(?:less\s+than|fewer\s+than|under)\s*$", re.I)
_RANGE = re.compile(_NUM + r"\s*(?:字|文字)?\s*(?:[~〜\-–—−]|から)\s*" + _NUM + r"\s*" + _UNIT, re.I)
_QUANT = re.compile(_NUM + r"\s*" + _UNIT, re.I)
_COUNT_NOUN = re.compile(r"(?:文字数|字数)[^0-9]{0,8}" + _NUM + r"\s*(?=以内|以下|まで|未満)")


# 上限が指す「欄」の語。短い欄（題名・名称・コメント）の上限を、提出物の本文全体の上限として使わない
_OTHER_SUBJECT = re.compile(
    r"タイトル|題名|表題|作品名|プロジェクト名|サービス名|アプリ名|プロダクト名|チーム名|団体名|名称|名前|氏名|キャッチ|一言|ひとこと|見出し|"
    r"ハッシュタグ|コメント|キャプション|サブタイトル|"
    r"\btitles?\b|\bnames?\b|\btagline\b|\bslogan\b|\bheadline\b|\bcomments?\b|\bcaption\b|\bhashtags?\b|\bsubtitle\b",
    re.IGNORECASE,
)
_DESCRIPTION_SUBJECT = re.compile(
    r"説明|概要|紹介|本文|文章|記述|要約|アピール|解説|詳細|内容|"
    r"description|overview|summary|abstract|introduction|pitch|write-?up|narrative|body\s+text",
    re.IGNORECASE,
)
# 文字数でない別の単位の数量（語・words・ワード・単語・バイト・行）。数値の直後にある時だけ
_OTHER_UNIT = re.compile(r"\d\s*(?:語|ワード|単語|バイト|行|words?(?![a-z])|bytes?(?![a-z])|lines?(?![a-z]))", re.IGNORECASE)
_WIDTH_AGNOSTIC = re.compile(
    r"問わず|問いません|関係なく|関係ありません|区別なく|区別せず|区別しません|区別はしません|区別はありません|"
    r"(?:とも|ともに|いずれも|どちらも)\s*1|regardless|each\s+counts?\s+as",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LimitSpec:
    limit: int | None  # 許される最大の字数（「未満」は N-1）
    exclusive: bool
    reason: str  # limit が None の理由（facts と確認不能の根拠に使う短い識別子）
    candidates: int = 0
    basis: str = "char"  # 数え方の基準: "char"（1字=1）／"fullwidth"（半角=0.5字）／"halfwidth"（全角=2字）


def _to_int(num: str) -> int:
    return int(num.replace(",", ""))


def extract_limit(quote: str) -> LimitSpec:
    """検証済み引用の文字列から、字数の上限を1つ取り出す。決められない時は limit=None と理由。"""
    text = unicodedata.normalize("NFKC", quote)
    uppers: dict[int, bool] = {}  # 値 → 未満か
    flags = {"lower": False, "approx": False}
    taken: list[tuple[int, int]] = []

    def role(start: int, end: int) -> str | None:
        """数値の前後の語から、上限(upper/strict)・下限(lower)・目安(approx)・不明(None)を決める。"""
        post = text[end : end + _AFTER]
        pre = text[max(0, start - 14) : start]
        if _UPPER_POST.match(post):
            return "strict" if _STRICT_POST.match(post) or _STRICT_PRE.search(pre) else "upper"
        if _LOWER_POST.match(post):
            return "lower"
        if _APPROX_POST.match(post):
            return "approx"
        if _UPPER_PRE.search(pre):
            return "strict" if _STRICT_PRE.search(pre) else "upper"
        if _LOWER_PRE.search(pre):
            return "lower"
        return None

    def add(value: int, r: str | None) -> None:
        if r in ("upper", "strict"):
            uppers[value] = uppers.get(value, False) or r == "strict"
        elif r in ("lower", "approx"):
            flags[r] = True

    for m in _RANGE.finditer(text):  # 400~800字 → 上限は後ろの数値（目安・下限の語が付く時はそれに従う）
        taken.append(m.span())
        add(_to_int(m.group(2)), role(m.start(2), m.end()) or "upper")
    for m in _QUANT.finditer(text):
        if any(a <= m.start() < b for a, b in taken):
            continue
        taken.append(m.span())
        add(_to_int(m.group(1)), role(m.start(), m.end()))
    for m in _COUNT_NOUN.finditer(text):  # 「文字数は800以内」（単位が数値の後ろに無い形）
        if any(a <= m.start(1) < b for a, b in taken):
            continue
        add(_to_int(m.group(1)), role(m.start(1), m.end(1)))

    valid = {v: strict for v, strict in uppers.items() if 1 <= v <= _MAX_LIMIT}
    if valid and _OTHER_UNIT.search(text):  # 同じ文に別の単位（語・行など）の上限がある。どれが提出物に当たるか決められない
        return LimitSpec(None, False, "other_unit", len(valid))
    if valid and _OTHER_SUBJECT.search(text) and not _DESCRIPTION_SUBJECT.search(text):
        return LimitSpec(None, False, "other_subject", len(valid))  # 題名・名称などの上限。本文全体の上限ではない
    basis = "char"
    if valid and ("全角" in text or "半角" in text) and not _WIDTH_AGNOSTIC.search(text):
        if "全角" in text and "半角" in text:  # 全角・半角で重みが違う数え方が両方ある。単純に1字=1で比べられない
            return LimitSpec(None, False, "width_dependent", len(valid))
        basis = "fullwidth" if "全角" in text else "halfwidth"
    if len(valid) == 1:
        ((value, strict),) = valid.items()
        return LimitSpec(value - 1 if strict else value, strict, "", 1, basis)
    if len(valid) > 1:
        return LimitSpec(None, False, "ambiguous_limit", len(valid))
    if flags["approx"]:
        return LimitSpec(None, False, "approximate_only")
    if flags["lower"]:
        return LimitSpec(None, False, "lower_bound_only")
    return LimitSpec(None, False, "no_upper_limit")


# --- 観測にする --------------------------------------------------------------------------------
def measure(counts: CharCounts, limit: int, basis: str = "char") -> tuple[ObsCode, ObsOutcome, bool]:
    """字数と上限 → (code, outcome, strong)。

    basis="char": 最小の数え方（空白なし・書記素）でも超えれば不適合、最大の数え方（空白あり・UTF-16）でも収まれば適合。
    basis="fullwidth": 不適合の側は「半角を0.5字」に換算した最小（fw_min2 > 上限×2）で、適合の側は従来の最大（全部1字）で決める。
    basis="halfwidth": 不適合の側は従来の最小（どの文字も1以上なので下限として有効）で、適合の側は「全角を2字」に換算した最大（hw_max）で決める。
    """
    if basis == "fullwidth":
        over, within = counts.fw_min2 > 2 * limit, counts.units_max <= limit
    elif basis == "halfwidth":
        over, within = counts.units_min > limit, counts.hw_max <= limit
    else:
        over, within = counts.units_min > limit, counts.units_max <= limit
    if over:
        return ObsCode.OVER_LIMIT, ObsOutcome.FAIL, True
    if within:
        return ObsCode.WITHIN_LIMIT, ObsOutcome.PASS, True
    return ObsCode.LIMIT_UNDECIDABLE, ObsOutcome.INCONCLUSIVE, False


def _obs(
    req: VerifiedRequirement,
    doc: SanitizedDoc,
    obs_id: str,
    code: ObsCode,
    outcome: ObsOutcome,
    facts: dict[str, bool | int | str],
    *,
    strong: bool = False,
) -> Observation:
    return Observation(
        obs_id=obs_id,
        tool=ToolName.RUN_CHECK,
        checker=Checker.TEXT_LENGTH,
        req_id=req.req_id,
        doc_id=doc.doc_id,
        code=code,
        outcome=outcome,
        strong=strong,
        facts=facts,
    )


def check_text_length(req: VerifiedRequirement, doc: SanitizedDoc, obs_id: str) -> Observation:
    """doc（提出物の説明文のページ）の可視テキストの字数を、req の検証済み引用にある上限と比べる。

    引用が無い（推測）・上限の数値が引用に無い／複数ある時は NO_PARAMETER（不確定）。本文は観測に載せない。
    """
    if req.span is None:
        return _obs(req, doc, obs_id, ObsCode.NO_PARAMETER, ObsOutcome.INCONCLUSIVE, {"why": "no_quote"})
    spec = extract_limit(req.span.original_span)
    if spec.limit is None:
        facts: dict[str, bool | int | str] = {"why": spec.reason}
        if spec.candidates:
            facts["candidates"] = spec.candidates
        return _obs(req, doc, obs_id, ObsCode.NO_PARAMETER, ObsOutcome.INCONCLUSIVE, facts)
    counts = count_chars(doc.visible_text)
    code, outcome, strong = measure(counts, spec.limit, spec.basis)
    masked = INJECTION_PLACEHOLDER in doc.visible_text
    if masked and code is ObsCode.WITHIN_LIMIT:  # 置換で縮んだ本文の字数は下限。「以内」とは言えない
        code, outcome, strong = ObsCode.LIMIT_UNDECIDABLE, ObsOutcome.INCONCLUSIVE, False
    return _obs(
        req,
        doc,
        obs_id,
        code,
        outcome,
        {
            "limit": spec.limit,
            "exclusive": spec.exclusive,
            "chars_with_ws": counts.chars_with_ws,
            "chars_no_ws": counts.chars_no_ws,
            "over_with_ws": counts.chars_with_ws > spec.limit,
            "over_no_ws": counts.chars_no_ws > spec.limit,
            "units_min": counts.units_min,
            "units_max": counts.units_max,
            "basis": spec.basis,
            "masked": masked,
            "truncated": doc.truncated,
        },
        strong=strong,
    )
