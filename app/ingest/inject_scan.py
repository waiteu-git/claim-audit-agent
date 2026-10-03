"""偽命令（プロンプトインジェクション）の検知（設計 §5-2 層1。補助線であり主防御は構造）。

走査は「検知してフラグ（スパン）を返す」だけで、本文は書き換えない。置換（〔注入疑い〕）は neutralize() が別に行う
（sanitize が呼ぶ。既定は書き換えない。コーパステストを通るまで置換を既定にしない運用のため）。

誤検知を抑える方針（§5-2: 単語単体は使わない）:
  * パターンは「命令の形（無視せよ・報告せよ・取得せよ）＋命令の対象（以前の指示・全件適合・URL）」の複合に限る。
  * 「必ず」「してください」「AIエージェント」「システムプロンプト」など、要項に普通にある語だけでは反応しない。
  * 「無視した場合は失格」のような条件文・禁止文は、命令形の語尾を要求して外す。
走査は引用検証と同じ思想の正規化（NFKC・大文字小文字・ゼロ幅/制御文字の除去）に、見た目だけ似せる細工の畳み込み
（アクセント記号・キリル/ギリシャの似た字・小型大文字・不可視の塗りつぶし文字）を足した文字列で行い、
一致位置を原文のオフセットへ戻す（分割タグ・ゼロ幅・全角を一括で潰す）。
  * tight  : 空白も除く（日本語パターン用。ソース上の改行・空白で語が割れても拾う）
  * spaced : 空白は1個に畳む（英語パターン用。単語境界を保つ）
  * core   : 英数字と漢字などの文字だけ（記号・空白・ハイフン・不可視文字を全部除き、1337 風の数字も戻す）。
             「i g n o r e」「ig-nore」「ign0re」のような割り・置換に耐える。誤検知を避けるため、長い定型句
             （以前の指示を無視せよ・全要件を適合とせよ・各言語の同義文）だけに使う。

限界（説明文にも書く）: 命令文の言い換えは「定型句」の範囲だけ（日英と主要な数か国語の「以前の指示を無視せよ」「全件適合と報告せよ」
の型）。画像内の文字・暗号化や逆順・文脈を読まないと分からない誘導・対応していない言語・core 以外の型を語の途中の記号で割る細工
（"Reve-al your system prompt" など）は拾えない。引用された攻撃例（説明文の中の「以前の指示を無視せよ」）と本物の攻撃文は区別できず、
どちらも検知する（置換は既定で無効）。拾えなくても、読むモデルはツールを持たないので影響は出力フィールドに限られる
（構造で止まる）。
"""
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

from app.textsafe import INJECTION_PLACEHOLDER

# 近接した一致を1つの検知にまとめる間隔（原文の文字数）。1つの注入文が複数パターンに当たっても1件に数える。
MERGE_GAP = 20

_COMBINING = r"\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f\u3099\u309a\uff9e\uff9f"
# 基底文字＋続く結合文字を1単位にして NFKC をかける（か＋゛→が、半角ｶ＋ﾞ→ガ のような合成を正しく扱う）
_CLUSTER = re.compile(rf"[^{_COMBINING}][{_COMBINING}]*|.", re.S)
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})
_DROP_CHARS = frozenset("*`")  # markdown の強調・コード記号
# 人に見えない文字（Cf ではない）。語の間に挟む空白の代わりにも、語の中に挟んで割る細工にも使える。
#   _FILLERS_DROP: 幅を持たず、語の中に挟むための文字（結合書記素ジョイナ・クメールの固有母音・モンゴル語の自由変化選択子）。無いものとして除く。
#   _FILLERS_DUAL: 空白の幅を持つ塗りつぶし文字（ハングル充填・点字の空白・物体置換）。空白の代わりにも語の中にも使われるので、
#                  spaced では「空白として読んだ表示」と「無いものとして読んだ表示」の両方で走査する（tight・core では他の空白と同じく消える）。
_FILLERS_DROP = frozenset("\u034f\u17b4\u17b5\u180b\u180c\u180d\u180f")
_FILLERS_DUAL = frozenset("\u115f\u1160\u2800\u3164\uffa0\ufffc")
_FILL = "\x00"  # _normalize が _FILLERS_DUAL に当てる印（NUL は本文に残らない）
# 1337 風の置き換え（core 表示だけ）。数字と記号を、それが似せている英字へ戻す。
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}


def _is_variation_selector(ch: str) -> bool:
    return "\ufe00" <= ch <= "\ufe0f" or "\U000e0100" <= ch <= "\U000e01ef"


# 見た目が似た字を英字へ畳む（NFKC・casefold の後）。キリル/ギリシャの似た字・小型大文字・ドット無しの i など。
# 写像は決定的でありさえすればよい: 同じ関数をパターンの文字にもかけるので、キリル語のパターンもそのまま照合できる。
_FOLD: dict[str, str] = {}
_FOLD.update(zip("аеорсухіјѕԁһԛԝѵкмнт", "aeopcyxijsdhqwvkmht"))  # キリルの似た字（小文字）
_FOLD.update(zip("οανρτυικχεημβγω", "oavptuikxenmbyw"))  # ギリシャ（小文字）
_FOLD.update(zip("ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡʏᴢ", "abcdefghijklmnopqrstuvwyz"))  # 小型大文字
_FOLD.update({"ı": "i", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ſ": "s", "ø": "o", "đ": "d", "ł": "l", "æ": "ae", "œ": "oe", "ð": "d", "þ": "th"})


@lru_cache(maxsize=16384)
def _fold(ch: str) -> str:
    """NFKC・casefold 済みの1文字を、見た目が似た字へ畳む（アクセント記号の除去・似た字・小型大文字）。"""
    m = _FOLD.get(ch)
    if m is not None:
        return m
    if ch.isascii():
        return ch
    d = unicodedata.normalize("NFD", ch)
    if len(d) > 1 and d[0].isascii() and d[0].isalpha():
        return d[0]  # é・ì・ñ・ü など。仮名の濁点（か＋゛）は d[0] が ASCII でないので対象外
    return ch


@dataclass(frozen=True)
class InjectionMatch:
    """検知1件（併合後）。start/end は scan() に渡した文字列上のオフセット。"""

    pattern_id: str  # 区間の中で最も先頭に現れたパターン
    start: int
    end: int
    pattern_ids: tuple[str, ...]  # 併合した全パターン（重複なし・出現順）


class _View:
    """正規化後の文字列と、各文字が原文のどの区間に由来するかの対応表。"""

    __slots__ = ("text", "src_start", "src_end")

    def __init__(self) -> None:
        self.text: str = ""
        self.src_start: list[int] = []
        self.src_end: list[int] = []

    def span(self, a: int, b: int) -> tuple[int, int]:
        """正規化後の区間 [a, b) を原文の区間へ戻す。"""
        return self.src_start[a], self.src_end[b - 1]


_WS = " "
_BRK = "\n"  # 行・ブロックの区切り。spaced では空白、tight では消え、core では「文をまたがない」境目になる
_BRK_CHARS = frozenset("\n\r\x0b\x0c\x1e\x85\u2028\u2029")  # 0x1e は textsafe.BLOCK_SEP（ブロック境界）
_SENTENCE_END = frozenset(".!?。！？")
_BARRIER = "|"  # core 表示で文・行をまたがせない印（パターンはこの文字を含まない）


def _normalize(text: str) -> tuple[list[str], list[int], list[int]]:
    """text を文字ごとに正規化する。戻り値は (文字（空白は _WS）, 原文の開始, 原文の終了) の3つ組の並び。

    NFKC・casefold（全角半角・大文字小文字・合成）→ 見た目が似た字の畳み込み（アクセント・キリル/ギリシャ・小型大文字）
    → 不可視・制御文字の除去。空白と不可視の塗りつぶし文字は _WS。
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for m in _CLUSTER.finditer(text):
        c = m.group()
        s0, e0 = m.start(), m.end()
        if c.isascii():
            if c in _BRK_CHARS:
                chars.append(_BRK)
            elif c.isspace():
                chars.append(_WS)
            elif c in _DROP_CHARS or c < " " or c == "\x7f":
                continue
            else:
                chars.append(c.lower())
            starts.append(s0)
            ends.append(e0)
            continue
        latin_base = False
        for ch in unicodedata.normalize("NFKC", c).casefold():
            if ch in _BRK_CHARS:
                out = _BRK
            elif ch in _FILLERS_DUAL:
                out = _FILL
            elif ch.isspace():
                out = _WS
            elif ch in _DROP_CHARS or ch in _FILLERS_DROP or unicodedata.category(ch) in _DROP_CATEGORIES or _is_variation_selector(ch):
                continue
            elif unicodedata.combining(ch) and latin_base:
                continue  # 英字に付けた結合記号（i̇ のドットなど）は見た目だけの細工。仮名の濁点は latin_base でないので残る
            else:
                out = _fold(ch)
            chars.append(out)
            starts.append(s0)
            ends.append(e0)
            latin_base = out.isascii() and out.isalpha()
    return chars, starts, ends


def _spaced_without_fill(chars: list[str], starts: list[int], ends: list[int]) -> _View:
    """塗りつぶし文字（_FILL）を無いものとして読んだ spaced 表示。"""
    v = _View()
    out: list[str] = []
    prev_ws = True
    for ch, s, e in zip(chars, starts, ends):
        if ch == _FILL:
            continue
        if ch == _WS or ch == _BRK:
            if not prev_ws:
                out.append(_WS)
                v.src_start.append(s)
                v.src_end.append(e)
            prev_ws = True
            continue
        prev_ws = False
        for sub in ch:
            out.append(sub)
            v.src_start.append(s)
            v.src_end.append(e)
    while out and out[-1] == _WS:
        out.pop()
        v.src_start.pop()
        v.src_end.pop()
    v.text = "".join(out)
    return v


def _build_views(text: str) -> tuple[_View, _View, _View, _View | None]:
    """(spaced, tight, core, spaced の別読み) を返す。別読みは、空白の幅を持つ塗りつぶし文字があるときだけ作る
    （spaced は塗りつぶしを空白と読み、別読みは無いものと読む）。"""
    chars, starts, ends = _normalize(text)
    alt = _spaced_without_fill(chars, starts, ends) if _FILL in chars else None
    chars = [_WS if c == _FILL else c for c in chars]

    spaced, tight, core = _View(), _View(), _View()
    sp_chars: list[str] = []
    ti_chars: list[str] = []
    co_chars: list[str] = []
    prev_ws = True  # 先頭の空白は捨てる
    n = len(chars)
    for i, (ch, s, e) in enumerate(zip(chars, starts, ends)):
        if ch == _WS or ch == _BRK:
            if not prev_ws:
                sp_chars.append(_WS)
                spaced.src_start.append(s)
                spaced.src_end.append(e)
            prev_ws = True
            if ch == _BRK and co_chars and co_chars[-1] != _BARRIER:
                co_chars.append(_BARRIER)
                core.src_start.append(s)
                core.src_end.append(e)
            continue
        prev_ws = False
        # 折り畳みで複数文字になる字（æ → ae）は、どの文字も同じ原文の区間を指す
        for sub in ch:
            sp_chars.append(sub)
            spaced.src_start.append(s)
            spaced.src_end.append(e)
            ti_chars.append(sub)
            tight.src_start.append(s)
            tight.src_end.append(e)
            if sub.isalnum():
                co_chars.append(_LEET.get(sub, sub))
                core.src_start.append(s)
                core.src_end.append(e)
            elif sub in "@$":
                co_chars.append(_LEET[sub])
                core.src_start.append(s)
                core.src_end.append(e)
            elif sub in _SENTENCE_END and (sub in "。！？" or i + 1 >= n or chars[i + 1] in (_WS, _BRK)) and co_chars and co_chars[-1] != _BARRIER:
                co_chars.append(_BARRIER)  # 文の終わり（英語は直後が空白・行末のとき）。core の定型句は文をまたがない
                core.src_start.append(s)
                core.src_end.append(e)
    # 末尾の空白を捨てる
    while sp_chars and sp_chars[-1] == _WS:
        sp_chars.pop()
        spaced.src_start.pop()
        spaced.src_end.pop()
    spaced.text = "".join(sp_chars)
    tight.text = "".join(ti_chars)
    core.text = "".join(co_chars)
    return spaced, tight, core, alt


@dataclass(frozen=True)
class _Pat:
    pid: str
    view: str  # "tight"（日本語）| "spaced"（英語・URL・記号）| "core"（英数字・漢字だけ。長い定型句のみ）
    rx: "re.Pattern[str]"
    veto_before: "re.Pattern[str] | None" = None  # 直前24字がこれに当たれば、否定文脈として捨てる


_B_START = "(?<![a-z0-9_])"
_B_END = "(?![a-z0-9_])"


def _ascii_boundaries(rx: str) -> str:
    """\\b を ASCII だけの単語境界に置き換える。日本語の直前直後（"instructionsを…"）でも英単語の境界として扱う。

    語頭の \\b（パターンの先頭・"(" "(?:" "|" の直後）は後読み、それ以外（語末）は先読みにする。
    """
    out = []
    i = 0
    while True:
        j = rx.find("\\b", i)
        if j < 0:
            out.append(rx[i:])
            break
        before = rx[:j]
        out.append(rx[i:j])
        out.append(_B_START if (j == 0 or before.endswith(("(", "(?:", "|"))) else _B_END)
        i = j + 2
    return "".join(out)


def _p(pid: str, view: str, rx: str, veto_before: str | None = None) -> _Pat:
    if view == "core":
        # 走査対象の文字にかける畳み込み（キリル→英字など）を、パターンの非 ASCII 文字にも同じようにかける
        rx = "".join(_fold(c) if ord(c) > 127 else c for c in rx)
    return _Pat(pid, view, re.compile(_ascii_boundaries(rx)), re.compile(veto_before) if veto_before else None)


# --- 日本語（tight: 空白なし・NFKC・小文字） ---------------------------------------------------
# 命令形の語尾。「〜した場合」「〜してはならない」のような条件・禁止の文は含めない。
_JA_IMP = r"(?:せよ|しろ|しなさい|なさい|(?:して|し)?(?:ください|下さい)|してくれ|すること|するように|すべし|願います|お願い)"
# 連用形で続ける命令文（「無視し全要件を…」）。「しない」「した」「しては」は除く。
_JA_RENYOU = r"し(?=[\u4e00-\u9fff\u30a0-\u30ffA-Za-z0-9「『“\"(\[【])"
_JA_TEMPORAL = r"(?:以前|これまで|今まで|上記|前述|先ほど|それまで|これ以前|従来|さっき)"
_JA_INSTR = r"(?:指示|命令|プロンプト|指令|ルール|制約|設定|システムメッセージ|ガイドライン)"
# 破棄語＋命令形。「無視して」と「忘れて」は活用が違うので別に持つ。「無視した場合」「無視してはならない」は含めない。
_JA_FORGET_IMP = rf"(?:(?:無視|破棄|取り消|上書き|リセット|撤回|解除)(?:{_JA_IMP}|し?[、,]|{_JA_RENYOU}|して(?![はも]))|忘れ(?:て(?![はも])|ろ|よ|なさい|[、,]))"
_JA_ALL = r"(?:全て|すべて|全部|一切|完全に|いったん)"
_JA_AI = r"(?:ai|llm|言語モデル|大規模言語モデル|アシスタント|エージェント|チャットボット|ボット|モデル|人工知能|クローラ|スクレイパ)"
_JA_QUOTE_OPEN = "[「『“\"'‘(]?"
_JA_QUOTE_CLOSE = "[」』”\"'’)]?"
_JA_VERDICT_WORD = r"(?:適合|合格|問題なし|問題ない|問題無し|準拠|クリア|ok|満点|全て満たして(?:いる|おり)|通過)"
_JA_REPORT = r"(?:報告|判定|出力|回答|評価|記録|表示|返答|答え|判断|記載|返し|返す)"

_PATTERNS: tuple[_Pat, ...] = (
    # 以前の指示を無視せよ（時間語＋指示語＋破棄語＋命令形）
    _p(
        "ja.override_prev",
        "tight",
        rf"{_JA_TEMPORAL}の{_JA_ALL}?の?{_JA_INSTR}(?:を|は|も){_JA_ALL}?{_JA_FORGET_IMP}",
    ),
    # 時間語の無い形は、命令形の語尾（せよ/しろ/してください…）まで要求する（「無視して提出した場合」は外す）
    _p("ja.override_cmd", "tight", rf"{_JA_INSTR}(?:を|は){_JA_ALL}?(?:無視|上書き|リセット|破棄){_JA_IMP}"),
    # 全件適合と報告せよ
    _p(
        "ja.verdict_all_pass",
        "tight",
        rf"(?:全件|全要件|全項目|全条件|全基準|(?:すべて|全て|全部)(?:の(?:要件|項目|条件|基準))?|各要件|各項目)(?:を|は|が)?{_JA_QUOTE_OPEN}{_JA_VERDICT_WORD}{_JA_QUOTE_CLOSE}(?:と|として|で){_JA_REPORT}(?:{_JA_IMP}|し{_JA_IMP}|[、,])",
    ),
    # この作品に満点/最高評価を付けよ
    _p(
        "ja.verdict_score",
        "tight",
        rf"(?:満点|最高(?:点|評価|得点|スコア|ランク)|高評価|最高)(?:を|で|と|に)(?:つけ|付け|与え|出力|採点|評価|判定|報告|記録|設定|付与)(?:{_JA_IMP}|よ|ろ|ること|て(?:ください|下さい|くれ))",
    ),
    # 以下のURLを取得せよ（polite な「取得してください」は要項にあり得るので、命令形だけ）
    _p(
        "ja.fetch_cmd",
        "tight",
        r"(?:以下|次|下記|この|上記)の(?:url|リンク|アドレス|エンドポイント)(?:を|に|へ)(?:取得|フェッチ|fetch|ダウンロード)(?:せよ|しろ|しなさい)",
    ),
    _p("ja.fetch_cmd_url", "spaced", r"https?://\S{4,300}\s?(?:を|に)(?:取得|フェッチ|fetch|ダウンロード)(?:せよ|しろ|しなさい)"),
    # この文書を読んでいるAIへ
    _p(
        "ja.address_ai",
        "tight",
        rf"(?:この|本|上記の)(?:ページ|文書|サイト|テキスト|内容|ドキュメント|資料|記事|提出物)を(?:読ん|処理|評価|審査|要約|解析|分析|クロール|スクレイピング|参照|確認|レビュー|採点)(?:で|し|して)?(?:いる|する|しよう(?:と)?している|している|中の)?{_JA_AI}(?:の?(?:皆様|各位|さん|殿|方)|へ|に(?:向け|対し)て?)?",
    ),
    # 【AIへの指示】のようなラベル形（直後が : や 】）。「AIへの指示の書き方」のような普通の文は外す
    _p(
        "ja.address_label",
        "tight",
        rf"{_JA_AI}(?:へ|向け|宛て?)の?(?:指示|命令|メッセージ|お願い|連絡|注意|注記|通達|プロンプト|重要事項)?[:】\]」』]",
    ),
    _p(
        "ja.authority",
        "tight",
        rf"(?:システム|運営|管理者|開発者|主催者)(?:から|より){_JA_AI}(?:への|に対する)(?:緊急|重要|最優先)の?(?:指示|命令|連絡|メッセージ)",
    ),
    _p(
        "ja.reveal_prompt",
        "tight",
        rf"(?:あなた|君|お前|貴方|あなた自身)の(?:システムプロンプト|システムメッセージ|初期プロンプト|隠し(?:プロンプト|指示)|内部(?:プロンプト|指示)|設定プロンプト)(?:を|は)(?:全文)?(?:表示|出力|開示|教え|見せ|漏らし|暴露|公開|書き出)(?:{_JA_IMP}|て(?:ください|下さい|くれ))",
    ),
    _p(
        "ja.role_hijack",
        "tight",
        rf"(?:(?:あなた|君|お前|{_JA_AI})(?:は|を|に)(?:今から|これから|これより)?(?:開発者|デベロッパー|デバッグ|管理者|神|dan|脱獄)モード(?:に入|になり|で動作|にし|へ移行|を有効)"
        rf"|(?:制限|ルール|ガイドライン|倫理)の?(?:ない|なし|無し){_JA_AI}(?:として|になり))",
    ),
    _p(
        "ja.tool_call",
        "tight",
        r"(?:fetch_link|http_probe|run_check|mark_unverifiable|fetch_url)(?:を|で)?(?:呼び出|実行|使用|コール)",
    ),
    # --- 英語（spaced: 空白1個・小文字） -----------------------------------------------------
    _p(
        "en.override_prev",
        "spaced",
        r"\b(?:ignore|disregard|forget|override|bypass|discard|overrule|neglect)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}"
        r"(?:previous|prior|above|earlier|preceding|former|original|initial|system)\s+(?:\w+\s+)?"
        r"(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?|commands?|constraints?|programming|messages?\s+from\s+the\s+system)\b",
    ),
    _p(
        "en.override_do_not_follow",
        "spaced",
        r"\b(?:do\s+not|don'?t|stop)\s+(?:follow|following|obey|obeying)\s+(?:(?:all|any|the|your|my)\s+){0,2}"
        r"(?:previous|prior|above|earlier|original|system)\s+(?:instructions?|prompts?|rules?|directions?|guidelines?)\b",
    ),
    _p(
        "en.override_all",
        "spaced",
        r"\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:above|before\s+this|you\s+(?:were|have\s+been)\s+told|prior\s+to\s+this)\b",
    ),
    _p(
        "en.reveal_prompt",
        "spaced",
        r"\b(?:reveal|print|show|display|output|repeat|disclose|leak|dump|reproduce)\s+(?:me\s+)?your\s+(?:full\s+|entire\s+|complete\s+|hidden\s+|secret\s+)?"
        r"(?:system\s+prompt|system\s+message|initial\s+instructions|hidden\s+instructions|developer\s+(?:message|prompt|instructions))\b",
        veto_before=r"(?:\bnot|n't|\bnever|\bwithout|\bavoid|\bprevent|\bunless)\s*$",
    ),
    _p(
        "en.role_hijack",
        "spaced",
        r"\b(?:you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken|uncensored|dan\b)"
        r"|you\s+(?:are|will)\s+(?:now\s+)?(?:in|enter)\s+(?:developer|debug|admin|god|dan|jailbreak)\s+mode"
        r"|(?:dan|jailbreak(?:en)?)\s+mode\s+(?:enabled|activated|on)"
        r"|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|jailbroken)"
        r"|pretend\s+(?:that\s+)?you\s+(?:are|have)\s+no\s+(?:restrictions|rules|guidelines))",
    ),
    _p(
        "en.verdict_all_pass",
        "spaced",
        r"\b(?:report|mark|rate|score|evaluate|judge|classify|label|record|output|respond|answer|return|state|declare|grade|assess)\s+"
        r"(?:all|every|each|the\s+entire)\s+(?:of\s+)?(?:the\s+)?(?:requirements?|items?|criteria|checks?|conditions?|rules?|constraints?)\s+"
        r"(?:as|with|to\s+be)\s+(?:being\s+)?[\"'“‘]?(?:compliant|conforming|conformant|passing|passed|pass|satisfied|met|ok|fulfilled|approved|valid)\b",
    ),
    _p(
        "en.verdict_all_pass_that",
        "spaced",
        r"\b(?:conclude|declare|report|state|say|answer|respond)\s+that\s+(?:all|every)\s+(?:of\s+the\s+)?(?:requirements?|items?|criteria|checks?)\s+(?:are|were|have\s+been)\s+(?:met|satisfied|compliant|passed|fulfilled)\b",
    ),
    _p(
        "en.verdict_score",
        "spaced",
        r"\b(?:give|assign|award|grant)\s+(?:this|the|my|our)\s+(?:submission|project|entry|app|application|work|page|site)\s+(?:a\s+|the\s+)?"
        r"(?:perfect|full|maximum|highest|top|max)\s+(?:score|marks?|rating|grade|points?)\b",
    ),
    _p(
        "en.verdict_rate",
        "spaced",
        r"\b(?:rate|score|evaluate|judge|grade)\s+(?:this|the)\s+(?:submission|project|entry|app|work)\s+(?:as\s+)?"
        r"(?:excellent|perfect|the\s+best|outstanding|flawless|10/10|100%)\b",
    ),
    _p(
        "en.fetch_cmd",
        "spaced",
        r"\b(?:you\s+(?:must|shall|will)|you\s+are\s+required\s+to|immediately|first,?)\s+(?:fetch|retrieve|request|load)\s+(?:the\s+)?(?:following\s+|this\s+)(?:url|link|endpoint)\b",
    ),
    _p(
        "en.address_ai",
        "spaced",
        r"\b(?:ai|llm|large\s+language\s+model|language\s+model|assistant|chatbot|bot|model|agent|crawler|scraper|summari[sz]er)s?\s+"
        r"(?:that\s+(?:is\s+)?|which\s+is\s+)?(?:reading|processing|summari[sz]ing|analy[sz]ing|scraping|crawling|parsing|evaluating|grading|judging|assessing|reviewing)\s+"
        r"(?:this|the\s+following|the\s+above)\s+(?:page|document|text|content|site|website|submission|project|entry)\b",
    ),
    _p(
        "en.address_label",
        "spaced",
        r"(?:^|[\s\[(<])(?:note|message|instructions?|attention|important|notice|attn|directive|prompt)s?\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?"
        r"(?:(?:ai|llm|language\s+model|large\s+language\s+model)(?:\s+(?:agent|assistant|model|system|reviewer|evaluator|grader|judge)s?)?|assistants?|chatbots?)\s*[:\]>)\-]",
    ),
    _p(
        "en.exfil_secret",
        "spaced",
        r"\b(?:send|post|upload|transmit|forward|exfiltrate|leak)\s+(?:(?:me|the|all|your|this|any)\s+){0,2}"
        r"(?:conversation|system\s+prompt|api[\s-]?keys?|secrets?|credentials?|tokens?|chat\s+history|previous\s+messages|hidden\s+prompt|environment\s+variables)\s+"
        r"(?:to|at|via|into)\s+(?:the\s+)?(?:url|endpoint|webhook|address|server|https?://)",
    ),
    # クエリに {…} の差し込み枠を持つURL（持ち出しの定型）。パスの {id} は API 表記として普通にあるので対象外
    _p("any.url_placeholder", "spaced", r"https?://\S{0,200}\?\S{0,100}=(?:\{\{?[^{}\s]{1,40}\}\}?|%7b[^\s]{1,40}%7d|\$\{[^{}\s]{1,40}\})"),
    # チャットテンプレートの区切りトークン（普通の文書には出ない）
    _p(
        "any.chat_template",
        "spaced",
        r"(?:<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|begin_of_text|start_header_id|end_header_id)\|>|\[/?inst\]|<<\s*/?sys\s*>>|<(?:start|end)_of_turn>)",
    ),
    # ツール呼び出しを装う記述
    _p("any.tool_markup", "spaced", r"(?:[<\[]/?(?:tool_?calls?|function_?calls?|tool_?use|tool_?result)[>\]]|\"(?:tool_calls?|function_call|tool_use)\"\s*:)"),
    _p(
        "any.tool_name_call",
        "spaced",
        r"(?:\"(?:name|function|tool)\"\s*:\s*\"(?:fetch_link|http_probe|run_check|mark_unverifiable|fetch_url)\""
        r"|\b(?:call|invoke|run|execute|use|trigger)\s+(?:the\s+)?(?:tool|function)\s+[`\"']?(?:fetch_link|http_probe|run_check|mark_unverifiable|fetch_url)\b"
        r"|\b(?:fetch_link|http_probe|run_check|mark_unverifiable|fetch_url)\s*\()",
    ),
    # --- 追加（敵対レビュー）: 割り・置換・言い換え・他言語に強い定型句（core 表示） ---------------------------------
    _p(
        "any.core_override_prev",
        "core",
        r"(?:ignore|disregard|forget|override|bypass|discard|overrule|neglect|dismiss|abandon|setaside|putaside|throwaway|paynoattentionto|paynoheedto|"
        r"donotfollow|dontfollow|stopfollowing|donotobey|donotheed|dontheed|donotconsider|donottakeintoaccount)"
        r"(?:all|any|every|the|your|my|these|those|of){0,3}"
        r"(?:previous|prior|above|earlier|preceding|former|original|initial|system|existing|aforementioned)"
        r"(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?|commands?|constraints?|programming|orders?)",
    ),
    _p(
        "any.core_override_everything",
        "core",
        r"(?:ignore|disregard|forget)(?:everything|all)(?:above|beforethis|priortothis|youwere(?:told|given|programmedwith)|youhave(?:been)?(?:told|given)|youve(?:been)?(?:told|given))",
    ),
    _p(
        "any.core_verdict_all",
        "core",
        r"(?:report|mark|rate|score|evaluate|judge|classify|label|record|output|respond|answer|return|state|declare|grade|assess|treat|consider|regard|count|deem|say|conclude|set)"
        r"(?:all|every|each|theentire|everything)(?:of)?(?:the)?(?:requirements?|criteria|checks?|conditions?|rules?|constraints?)"
        r"(?:as|with|tobe|being|are|is|were)?(?:compliant|conforming|conformant|passing|passed|pass|satisfied|met|fulfilled|approved|valid)",
    ),
    _p(
        "any.override_prev_xlang",
        "core",
        # 中国語・韓国語・スペイン語・フランス語・ドイツ語・ロシア語・ポルトガル語・イタリア語の「以前の指示を無視せよ」
        r"(?:(?:忽略|无视|無視|忘记|忘記|不要理会|不要理會)(?:之前|以前|上面|先前|以上|前面|此前)(?:的)?(?:所有|全部|一切|任何)?(?:的)?(?:指令|指示|提示|规则|規則|说明|說明|命令|约束|約束)"
        r"|(?:이전|위의|앞의|기존)(?:의)?(?:모든)?(?:지시|명령|지침|프롬프트|규칙)(?:사항|들)?(?:을|를|은|는)?(?:모두)?(?:무시|잊|따르지)"
        r"|(?:ignora|ignorar|ignore|olvida|olvidar|omite)(?:todas)?(?:las|tus|sus)?(?:instrucciones|indicaciones|reglas|ordenes|directrices)(?:anteriores|previas)"
        r"|(?:ignore|ignorez|ignorer|oublie|oubliez|oublier)(?:toutes)?(?:les|tes|vos)?(?:instructions|consignes|regles|directives)(?:precedentes|anterieures|cidessus)"
        r"|(?:ignoriere|ignorieren|ignorier|vergiss|vergessen)(?:alle|alles)?(?:vorherigen|bisherigen|obigen|fruheren|vorigen)(?:anweisungen|instruktionen|regeln|befehle|vorgaben)"
        r"|(?:игнорируй|игнорируйте|забудь|забудьте)(?:все)?(?:предыдущие|прежние|вышеуказанные|прошлые)(?:инструкции|указания|правила|команды)"
        r"|(?:ignore|ignora|ignorar|esqueca)(?:todas)?(?:as)?(?:instrucoes|regras|ordens)(?:anteriores|previas)"
        r"|(?:ignora|ignorate|dimentica)(?:tutte)?(?:le)?(?:istruzioni|regole)(?:precedenti|sopra))",
    ),
    # --- 追加: 英語（spaced） ---------------------------------------------------------------------------------
    _p(
        "en.override_bare",
        "spaced",
        r"\b(?:ignore|disregard|forget|dismiss)\s+(?:all|any|every)\s+(?:of\s+)?(?:(?:your|the|my)\s+)?"
        r"(?:instructions?|prompts?|rules?|directions?|guidelines?|commands?|constraints?)\s*(?:[.,;:!]|and\b|then\b|now\b|instead\b|$)",
    ),
    _p(
        "en.override_your",
        "spaced",
        r"\b(?:ignore|disregard|forget|dismiss)\s+(?:your|my)\s+(?:instructions?|prompts?|programming|guidelines?|rules?)\s*(?:[.,;:!]|and\b|then\b|now\b|instead\b|$)",
    ),
    _p(
        "en.override_context",
        "spaced",
        r"\b(?:ignore|disregard|forget)\s+(?:(?:all|any|the|your)\s+){0,2}(?:previous|prior|above|earlier)\s+(?:context|conversation)\b",
    ),
    _p(
        "en.override_donot_use",
        "spaced",
        r"\b(?:do\s+not|don'?t|never)\s+(?:use|apply|trust|rely\s+on)\s+(?:the\s+)?(?:above|previous|prior|earlier)\s+(?:instructions?|prompts?)\b"
        r"|\b(?:do\s+not|don'?t)\s+take\s+(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\s+into\s+account\b",
    ),
    _p(
        "en.override_trailing",
        "spaced",
        r"\b(?:ignore|disregard|forget|dismiss|override)\s+(?:(?:all|any|every|the|your|my)\s+){1,2}(?:instructions?|prompts?|rules?|directions?|guidelines?|commands?)\s+"
        r"(?:above|before|given\s+(?:above|before|earlier)|so\s+far|you\s+(?:were|have\s+been)\s+given)\b",
    ),
    _p(
        "en.override_everything_told",
        "spaced",
        r"\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:that\s+)?(?:you(?:\s+have\s+been|['’]ve\s+been|\s+were|\s+are)\s+(?:told|given|programmed\s+with)|i\s+(?:said|told\s+you)\s+before)\b",
    ),
    _p(
        "en.role_hijack_from_now",
        "spaced",
        r"\b(?:from\s+now\s+on|henceforth)\s*,?\s*you\s+(?:are|will\s+be|shall\s+be)\s+(?:an?\s+)?(?:dan\b|unrestricted|unfiltered|jailbroken|uncensored|evil|rogue)",
    ),
    _p(
        "en.decode_exec",
        "spaced",
        r"\b(?:decode|decrypt|deobfuscate|base64[\s-]?decode)\s+(?:this|the\s+following|the\s+text\s+below|the\s+string\s+below)\s+(?:base64|hex|rot13|encoded|encrypted|obfuscated|cipher)?"
        r".{0,60}?\s(?:and|then)\s+(?:follow|execute|obey|carry\s+out|act\s+on)\s+(?:it|them|the\s+instructions?|its\s+instructions?)\b",
    ),
    _p(
        "en.verdict_claim",
        "spaced",
        r"\b(?:say|state|declare|report|conclude|answer|respond|write|output|claim|assert|indicate)\s+that\s+this\s+(?:submission|project|entry|app|application|work|page|site)\s+"
        r"(?:meets?|satisfies|satisfy|complies?\s+with|passes?|fulfils?|fulfills?|has\s+passed)\s+(?:all|every)\s+(?:of\s+the\s+)?(?:requirements?|criteria|rules|checks|conditions)\b",
    ),
    _p(
        "en.answer_claim",
        "spaced",
        r"\b(?:the\s+)?(?:correct|right|expected|only\s+valid|true)\s+(?:answer|verdict|judg(?:e)?ment|result|response|output|evaluation)\s+(?:for|to)\s+(?:every|each|all)\s+(?:the\s+)?"
        r"(?:requirements?|items?|checks?|criteria|criterion)\s+(?:is|are)\s+[\"'“‘]?(?:compliant|conforming|passing|passed|pass|satisfied|met|ok|approved|valid)[\"'”’]?\s*(?:[.!]|$)",
    ),
    _p(
        "en.no_violations",
        "spaced",
        r"\b(?:say|state|report|declare|conclude|answer|respond|output|confirm|claim)\s+(?:that\s+)?(?:there\s+(?:are|were|is)\s+)?(?:no|zero)\s+(?:violations?|defects?|non-?compliances?|failures?)\b",
    ),
    _p(
        "en.reveal_question",
        "spaced",
        r"\bwhat\s+(?:are|were)\s+your\s+(?:system\s+)?(?:instructions|rules|guidelines|prompt)\s*\?\s*(?:please\s+)?(?:print|show|repeat|list|tell|output)\b",
    ),
    _p(
        "en.output_pass",
        "spaced",
        r"\b(?:output|respond|answer|reply)\s*(?:with|only|exactly)?\s*[:\-]?\s*[\"'“‘]?(?:all\s+requirements\s+(?:are\s+)?(?:met|satisfied|compliant|passed)|compliant|pass(?:ed)?|ok)[\"'”’]?"
        r"\s+(?:for|to)\s+(?:each|every|all)\s+(?:the\s+)?(?:requirements?|items?|criteria|checks?)\b",
    ),
    _p(
        "en.verdict_all_pass2",
        "spaced",
        r"\b(?:treat|consider|regard|count|deem|mark|set|report|state|declare|record|log|grade|rate|judge|classify|label|score|assume)\s+"
        r"(?:that\s+)?(?:all|every|each)\s+(?:of\s+)?(?:the\s+)?(?:requirements?|criteria|checks?|conditions?|rules?|constraints?)\s+(?:(?:as|to\s+be|with|being|are|is)\s+)*"
        r"[\"'“‘]?(?:compliant|conforming|conformant|satisfied|fulfilled|met|passed|passing|approved|valid)\b",
    ),
    _p(
        "en.reveal_above",
        "spaced",
        r"\b(?:repeat|print|output|show|display|reproduce|recite|copy)\s+(?:the\s+)?(?:words|text|content|message|everything)\s+above\s*"
        r"(?:[.!?,;:]|$|\s+(?:this\s+line|verbatim|word\s+for\s+word|starting\s+with|exactly|in\s+full)\b)",
        veto_before=r"(?:\bnot|n't|\bnever|\bwithout|\bavoid|\bprevent|\bunless)\s*$",
    ),
    _p("en.role_tag", "spaced", r"</?(?:system|developer)(?:[_-](?:prompt|message|override|instructions?))?>|\b(?:system|admin|developer)\s+override\s*[:\-—]"),
    # --- 追加: 日本語（tight） ---------------------------------------------------------------------------------
    _p(
        "ja.override_follow",
        "tight",
        rf"(?:{_JA_TEMPORAL}|前)の(?:全ての|すべての)?(?:指示|命令|プロンプト|指令)(?:に(?:は)?)従(?:わず|わないで(?:ください|下さい)?|うな)",
    ),
    _p(
        "ja.override_void",
        "tight",
        rf"(?:{_JA_TEMPORAL}|前)の(?:全ての|すべての)?(?:指示|命令|プロンプト|指令)(?:は|も)(?:全て|すべて)?(?:無効|無視|破棄|撤回|取り消し)(?:です|だ|とする|とします|となります|になります|として)",
    ),
    _p(
        "ja.override_then_verdict",
        "tight",
        rf"(?:指示|命令|ルール|プロンプト)(?:を|は)(?:全て|すべて)?(?:無視|破棄|上書き)(?:して|し)[、,]?(?:全件|全要件|全項目|すべて|全て|全部)(?:の(?:要件|項目))?(?:を|は|が)?"
        rf"{_JA_QUOTE_OPEN}{_JA_VERDICT_WORD}{_JA_QUOTE_CLOSE}(?:と|に|として|で)?(?:しろ|せよ|しなさい|しておけ|すること|するように|して(?:ください|下さい)|報告|判定|出力)",
    ),
    _p(
        "ja.verdict_satisfied",
        "tight",
        rf"(?:全件|全要件|全項目|全条件|全基準|(?:すべて|全て|全部)(?:の(?:要件|項目|条件|基準))?|各要件|各項目)(?:を|は|が)?{_JA_QUOTE_OPEN}(?:満たして(?:いる|おり)|満たす|満たした|クリアして(?:いる|おり)|通過して(?:いる|おり))"
        rf"{_JA_QUOTE_CLOSE}(?:と|として|旨を?)(?:報告|判定|出力|回答|評価|返答|答え)(?:{_JA_IMP}|し{_JA_IMP}|[、,])",
    ),
    _p(
        "ja.verdict_treat",
        "tight",
        rf"(?:全件|全要件|全項目|全条件|全基準|(?:すべて|全て|全部)(?:の(?:要件|項目|条件|基準))?|各要件|各項目)(?:を|は|が)?{_JA_QUOTE_OPEN}{_JA_VERDICT_WORD}{_JA_QUOTE_CLOSE}(?:と|として)"
        r"(?:扱え|扱うこと|扱って(?:ください|下さい)|扱うように|みなせ|みなすこと|みなして(?:ください|下さい)|みなすように|見なせ|見なすこと|見なして(?:ください|下さい)|見なすように|判断せよ|判断しろ|判断すること|認めよ|認めること)",
    ),
    _p(
        "ja.address_ai_cmd",
        "tight",
        rf"(?:ページ|文書|サイト|テキスト|内容|ドキュメント|資料|記事|提出物|作品|プロジェクト)を(?:読ん|処理|評価|審査|要約|解析|分析|クロール|スクレイピング|参照|確認|レビュー|採点)(?:で|し|して)?"
        rf"(?:いる|する|しよう(?:と)?している|している|中の)?{_JA_AI}(?:の皆様)?(?:は|が|へ|に)[、,]?(?:以下|次|下記|この)(?:の)?(?:指示|命令|手順|ルール|内容)(?:に|を)(?:従|守|実行|優先)",
    ),
    _p(
        "ja.reveal_prompt_bare",
        "tight",
        r"(?:システムプロンプト|システムメッセージ|初期プロンプト|隠しプロンプト|内部プロンプト|隠し指示|内部指示)(?:を|は)(?:全文|そのまま|すべて|全て)?(?:表示|出力|開示|暴露|書き出)(?:せよ|しろ)",
    ),
)

PATTERN_IDS: tuple[str, ...] = tuple(p.pid for p in _PATTERNS)
_PRIORITY = {p.pid: i for i, p in enumerate(_PATTERNS)}


def scan_hits(text: str) -> list[tuple[str, int, int]]:
    """併合前の一致（パターンID, start, end）。start/end は text 上のオフセット。テスト・調査用。"""
    if not text:
        return []
    spaced, tight, core, alt = _build_views(text)
    views = {"spaced": [spaced] + ([alt] if alt is not None else []), "tight": [tight], "core": [core]}
    hits: list[tuple[str, int, int]] = []
    seen: set[tuple[str, int, int]] = set()
    for pat in _PATTERNS:
        for v in views[pat.view]:
            if not v.text:
                continue
            for m in pat.rx.finditer(v.text):
                a, b = m.start(), m.end()
                if b <= a:
                    continue
                if pat.veto_before is not None and pat.veto_before.search(v.text[max(0, a - 24) : a]):
                    continue
                s, e = v.span(a, b)
                if pat.view == "core" and s > 0 and text[s - 1].isascii() and text[s - 1].isalnum():
                    continue  # 語の途中から始まる一致（gitignore の "ignore"・account の "count"）は捨てる
                if (pat.pid, s, e) not in seen:
                    seen.add((pat.pid, s, e))
                    hits.append((pat.pid, s, e))
    return hits


def scan(text: str, *, merge_gap: int = MERGE_GAP) -> list[InjectionMatch]:
    """text を走査し、近接する一致を併合した検知のリストを先頭からの順で返す。本文は書き換えない。"""
    hits = scan_hits(text)
    if not hits:
        return []
    hits.sort(key=lambda h: (h[1], _PRIORITY[h[0]], h[2]))
    merged: list[InjectionMatch] = []
    cur_ids: list[str] = []
    cur_s = cur_e = -1
    for pid, s, e in hits:
        if cur_ids and s <= cur_e + merge_gap:
            cur_e = max(cur_e, e)
            if pid not in cur_ids:
                cur_ids.append(pid)
            continue
        if cur_ids:
            merged.append(InjectionMatch(cur_ids[0], cur_s, cur_e, tuple(cur_ids)))
        cur_ids, cur_s, cur_e = [pid], s, e
    merged.append(InjectionMatch(cur_ids[0], cur_s, cur_e, tuple(cur_ids)))
    return merged


def limit_matches(matches: "list[InjectionMatch]", cap: int) -> "list[InjectionMatch]":
    """検知が cap 件を超えるとき、間隔の狭い隣同士を併合して cap 件以内にする。切り捨てない（区間は必ず覆う）。

    先頭から cap 件で打ち切ると、注入文を大量に並べて上限を使い切らせた後ろに本物を置く細工が、置換も重なり判定
    （P-INJ-01）もすり抜ける。併合した区間は広くなるが、その区間と重なる引用は棄却される（安全側）。
    """
    n = len(matches)
    if cap < 1 or n <= cap:
        return list(matches)
    gaps = sorted(range(n - 1), key=lambda i: matches[i + 1].start - matches[i].end, reverse=True)
    cut = set(gaps[: cap - 1])  # 最も広い cap-1 個の間隔だけを区切りとして残す
    out: list[InjectionMatch] = []
    first = 0
    for i in range(n):
        if i in cut or i == n - 1:
            group = matches[first : i + 1]
            ids: list[str] = []
            for m in group:
                for pid in m.pattern_ids:
                    if pid not in ids:
                        ids.append(pid)
            out.append(InjectionMatch(group[0].pattern_id, group[0].start, max(m.end for m in group), tuple(ids)))
            first = i + 1
    return out


def neutralize(text: str, matches: "list[InjectionMatch]") -> tuple[str, list[tuple[int, int]]]:
    """一致区間そのもの（前後に広げない）を INJECTION_PLACEHOLDER に置換する。段落全体は置換しない（§5-2）。

    戻り値は (置換後の文字列, 置換後の文字列上でのプレースホルダ区間のリスト)。matches は scan() の出力（重ならない）。
    """
    pieces: list[str] = []
    spans: list[tuple[int, int]] = []
    pos = 0
    out_len = 0
    for m in sorted(matches, key=lambda x: x.start):
        pieces.append(text[pos : m.start])
        out_len += m.start - pos
        pieces.append(INJECTION_PLACEHOLDER)
        spans.append((out_len, out_len + len(INJECTION_PLACEHOLDER)))
        out_len += len(INJECTION_PLACEHOLDER)
        pos = m.end
    pieces.append(text[pos:])
    return "".join(pieces), spans

