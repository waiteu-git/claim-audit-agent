"""入口の洗浄（設計 §5-2 層0・§3 ACQUIRE）。取得した非信頼 HTML を SanitizedDoc へ変換する。

出力（契約 app/contracts.py の SanitizedDoc）:
  * visible_text   可視テキストだけ。p/li/td/th/tr/h1-6/br ほかブロック要素の境界に U+001E を入れる（§5-1 S-02）。
                   ゼロ幅・bidi・タグ文字・制御文字は除去済み。索引化・Reader への入力はこれだけ。
  * hidden         可視テキストから分離した隠しチャネル（由来ごとに1本。本文は持たず、長さと sha256 だけ）。
  * links          リンク表（href は絶対URL化。anchor_text は非信頼）。隠しリンクは載せない。
  * page_class     コード算出（HTTP ステータス＋password 欄＋本文長＋script 数）。検査を減らす方向の分類は
                   強い証拠があるときだけ付ける（誤分類は「不適合」を「確認不能」へ洗浄するため）。
  * injection_signals  注入スキャナ（inject_scan）の検知。可視は visible_text 上の区間、隠しは channel の添字で指す。

設計の取り決め（G2 の範囲）:
  * 標準ライブラリの html.parser で自前の要素スタックを持つ。終了タグの扱いは HTML パーサ仕様に寄せ、迷う場面では
    「隠す側」へ倒す（隠れた要素を早く閉じて可視へ漏らすことはしない）。
  * 隠しチャネルへ分離するもの: script/style/noscript/template/title・HTML コメント・meta・属性値（alt/title/
    aria-label/placeholder/data-*/input の value ほか）・hidden/popover 属性・aria-hidden="true"・インライン style の
    display:none / visibility:hidden / opacity 0 付近 / 読めない小ささの文字 / 透明な文字色 / 画面外・切り抜き・大きさゼロ
    （詳細は css_hide）・input[type=hidden]・Unicode タグ文字と異体字セレクタの連なりをデコードした文字列・ブラウザが描画しない
    要素の中身（iframe/video/audio/canvas/object の代替表示、SVG の desc・defs・<svg> 直下の文字、MathML の annotation、
    <select> の option 以外の文字、<select> の外の option）。
  * 構文解析はブラウザの実測に合わせる（敵対レビューで、Chromium を正解にした差分試験を数万文書流して詰めた）:
    重複属性（最初が勝つ。隠しは重なった全部のどれか1つで隠す）・宣言の「最後が勝つ」を使わない（壊れた宣言や !important で
    隠しが外れて見える細工）・2つ目以降の <html>/<body> の属性は文書全体に効く・<!--> と <!---> の空コメント・script の二重
    エスケープ・noscript などの生テキスト・表の外の表要素の無視・li/dd/dt/option の暗黙の終了（スタックの先頭だけ）・
    </p> の button スコープ・</form> は上の要素を閉じない・書式要素（<b style="display:none"> など）は </p> などで閉じられても
    続く文字の前に再び開かれる・SVG/MathML の中の抜け出しタグと HTML 統合点・<select> の中の <select>/<input>。
  * <style> のクラス・id・タグの単純な規則（常に真の @media の中を含む）で隠れる要素も、submission では隠す
    （style_rules）。spec には掛けない（要項のレイアウト用の display:none が要件文を消すため）。
  * 文字コードはブラウザの規則に合わせる（BOM → ヘッダ → meta（先頭1024バイトのコメント外）。replacement 系の宣言は本文が
    見えない・UTF-16 の宣言と BOM 無しの UTF-16・meta の UTF-16 は UTF-8 扱い）。
  * 契約の HiddenKind に script/comment/属性などの種別が無いため、CSS 由来以外は OTHER に束ねる
    （由来の区別が要るなら T1 に種別の追加を依頼する）。
  * __NEXT_DATA__ のような JSON 本文データは、既定では隠しチャネルへ（設計どおり script は捨てる）。要項側（spec）だけ
    embedded_json="append_unseen" で、可視側に無い HTML 文字列を可視テキストへ追記できる（既定は無効。使うかは本人の裁定）。
    実測（2026-10-02・公開LPの保存HTML。Next.js Pages Router の SSR）: 概要・ルール・日程・資格・FAQ は SSR の可視HTMLにあるが、
    提出時の注意・エントリー説明・ルール概要の3欄は __NEXT_DATA__ にしか無い（手元の台帳の必須32件のうち6件がここ）。
  * 注入の置換（〔注入疑い〕）は neutralize_injections=True の時だけ（既定は書き換えない。コーパステストを通すまで）。
  * spec の「構造的な隠し（hidden 属性・タブ・アコーディオン）を可視扱い」は visible_hidden_kinds で差し込める（既定は空）。

限界（評価できないもの。説明文にも書く。主防御は構造であり、ここは補助線）:
  外部 CSS・var()・複雑なセレクタ・背景と同じ色の文字（親の背景）・JS が消す／足す文字・画像内の文字・iframe の srcdoc の中身
  （隠しチャネル扱い）・<details> の閉じた中身（要項のアコーディオンを落とさないよう可視扱い）・宣言的 Shadow DOM（隠し側へ倒す）。
"""
import codecs
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import quote, urljoin, urlsplit

from app.contracts import (
    ContentKind,
    DocRole,
    FetchOutcome,
    FetchResult,
    HiddenChannel,
    HiddenKind,
    InjectionSignal,
    LinkEntry,
    LinkRole,
    PageClass,
    PageSignals,
    SanitizedDoc,
    UrlPrefix,
)
from app.ingest import css_hide, inject_scan
from app.ingest.css_hide import hidden_kinds_from_style  # noqa: F401  公開名の互換（本体は css_hide）
from app.net.urlcheck import UrlRejected, in_scope, validate_url
from app.textsafe import BLOCK_SEP, escape_for_display, is_unsafe_char, strip_unsafe

# --- 閾値（定数。変えるなら tests も見直す） ----------------------------------------------------------
LOGIN_WALL_MAX_VISIBLE = 800  # password 欄／ログイン URL があり、可視文字数がこれ未満ならログイン壁
SPA_SHELL_MAX_VISIBLE = 200  # 可視文字数がこれ未満で script がある（＋マウント点か noscript か script 複数）なら SPA の殻
MAX_LINKS = 200  # リンク表の上限（LinkId は L1〜L999）
ANCHOR_MAX_CHARS = 200
MAX_SIGNALS_PER_DOC = 50
VISIBLE_SIGNAL_CAP = 40  # 可視の検知の上限。残り（10件以上）は隠しの検知のために残す
MAX_EMBEDDED_APPEND_CHARS = 100_000  # embedded_json で追記する可視テキストの合計上限
MAX_STYLE_CHARS = 400_000  # 1回目の走査で集める <style> の本文の合計上限
SNIPPET_CHARS = 60

JsonPolicy = Literal["hidden", "append_unseen"]

# --- タグの分類 ----------------------------------------------------------------------------------------
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_BLOCK = frozenset(
    "address article aside blockquote body br button caption center dd details dialog dir div dl dt fieldset figcaption figure "
    "footer form h1 h2 h3 h4 h5 h6 header hgroup hr html legend li main menu nav ol optgroup option p pre section select summary "
    "table tbody td tfoot th thead tr ul".split()
)
# 終了タグを「範囲内にあれば閉じ、無ければ無視」で扱う要素（ブロック等。実装上の近似）
_SPECIAL = _BLOCK | frozenset("head noscript script style template title textarea svg math".split())
# HTML パーサ仕様の special カテゴリそのもの。「li/dd/dt の暗黙の終了」「その他の終了タグ」の境界判定は仕様どおりにする
# （近似だと、隠れた li の中の section 内で始まった li を、ブラウザは隠れた li の子にするが、こちらは閉じて可視へ漏らす）。
_HTML_SPECIAL = frozenset(
    "address applet area article aside base basefont bgsound blockquote body br button caption center col colgroup dd details dir div dl dt "
    "embed fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html iframe img input keygen li "
    "link listing main marquee menu meta nav noembed noframes noscript object ol p param plaintext pre script search section select source "
    "style summary table tbody td template textarea tfoot th thead title tr track ul wbr xmp "
    # SVG/MathML の特別な要素（HTML 統合点）。これらを越える「その他の終了タグ」は無視される
    "desc foreignobject mi mo mn ms mtext annotation-xml".split()
)  # fmt: skip
_LI_EXEMPT = frozenset({"address", "div", "p"})  # li/dd/dt の暗黙の終了を止めない special 要素
# <p> を閉じる開始タグ。仕様では table も入るが、互換モード（<!DOCTYPE> の無い文書）では閉じない。どちらで描画されるかは
# 文書次第なので、隠れた <p> の中の表は「閉じない側（隠れたまま）」に固定する（標準モードなら表は見えるので、隠し過ぎの側）。
_P_CLOSERS = frozenset(
    "address article aside blockquote center details dialog dir div dl dd dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 "
    "header hgroup hr li main menu nav ol p pre section ul".split()
)
# 「アクティブな書式要素」（HTML 仕様の active formatting elements）。これらは終了タグ以外の理由（</p> など祖先の終了）で
# 閉じられても、続く文字や開始タグの前に再び開かれる。隠れた <b style="display:none"> が </p> で閉じられた後の文字は、
# ブラウザでは再び隠れた <b> の中に入る。実装が再開しないと、その文字が可視へ漏れる。
_FORMATTING = frozenset("a b big code em font i nobr s small strike strong tt u".split())
_AFE_MARKERS = frozenset("applet caption marquee object td template th".split())  # 再開の境界（要素が閉じるまで外側の書式は再開しない）
# 開始タグで書式要素の再開をしないもの（ブロック要素など。仕様の「その他の開始タグ」以外）
_NO_RECONSTRUCT = frozenset(
    "address article aside blockquote body caption center col colgroup details dialog dir div dl dd dt fieldset figcaption figure footer form "
    "frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html legend li listing main menu nav noscript ol optgroup option p plaintext pre "
    "section summary table tbody td tfoot th thead tr ul "
    "base link meta param source track script style template title textarea iframe noembed noframes".split()
)
_SCOPE_STOP = frozenset("applet caption html marquee object table td template th".split())
_TABLE_STOP = frozenset({"table", "template", "html"})
# ブラウザが描画しない要素。中の文字は人に見えない（子の文字は隠しチャネルへ）。
#   script/style/template/noscript/title/textarea/datalist/noembed/noframes: 文書の設計どおり
#   iframe/video/audio/canvas/object/applet/rp: 代替表示の子（対応ブラウザでは出ない）
#   desc/metadata/defs/symbol/clippath/mask/pattern/marker/gradient/filter・annotation: SVG/MathML の非描画の子
_HIDDEN_TAGS = frozenset(
    "script style template noscript title textarea datalist noembed noframes iframe video audio canvas object applet rp "
    "desc metadata defs symbol clippath mask pattern marker lineargradient radialgradient filter annotation annotation-xml".split()
)
# HTML の「抜け出し」タグ（SVG/MathML の中で現れると、仕様では外側の SVG/MathML を閉じて HTML の本文へ戻る）。
# 「/>」の自己閉じも、これらは HTML 要素として扱われて無視される（閉じない）。
_FOREIGN_BREAKOUT = frozenset(
    "b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr i img li listing menu meta nobr ol p pre ruby s small "
    "span strong strike sub sup table tt u ul var".split()
)
# SVG/MathML の中で、文字が描画される場所（SVG の text 系・foreignObject・MathML の token 要素）と、抜け出した HTML。
# それ以外（<svg> や <g> の直下の文字など）の文字は描画されない。
_FOREIGN_TEXT_OK = frozenset("text tspan textpath foreignobject mi mn mo ms mtext".split()) | _FOREIGN_BREAKOUT
# 子の開始タグを HTML として解析し直す要素（HTML 統合点）。SVG の foreignObject/desc/title、MathML の token 要素。
_FOREIGN_INTEGRATION = frozenset("foreignobject desc title mi mo mn ms mtext annotation-xml".split())
# 終了タグを「その他の終了タグ」として扱う要素（間に special 要素があれば無視。スコープ付きではない）
_OTHER_END = frozenset({"option", "optgroup", "legend", "svg", "math"})
_RUBY_PARTS = frozenset({"rb", "rt", "rp", "rtc"})
# <select> の中（select モード）で無視されない開始タグ。option・optgroup・hr・入れ子の select/input などと、生テキスト・外来・
# 「境界」になる要素（Chromium の実測: これら以外は無視されて、中の文字は select の直下の文字になる）
_SELECT_KEEPS = frozenset(
    "option optgroup hr select input keygen textarea script style template iframe noscript noembed noframes xmp plaintext object marquee applet svg math table".split()
)
_TABLE_END = frozenset("caption table tbody tfoot thead tr td th".split())
_CLOSES_SELECT = frozenset({"input", "keygen"})  # <select> の中で始まると select を閉じる（Chromium で実測。表・textarea・div などは閉じない）
_TABLE_ONLY = frozenset("caption col colgroup tbody td tfoot th thead tr".split())  # 表の外では、ブラウザは開始タグごと無視する
# 中身がマークアップでなく生の文字になる要素（スクリプトが有効なブラウザの構文解析）。html.parser の版によっては
# 一部が通常のタグとして解析される（noscript は全版で）ので、こちらで明示して生テキストモードへ入れる。
# 通常のタグとして解析すると、中の <h2> などが「外側の <p> を閉じる」暗黙の終了を起こし、隠れた noscript ごと閉じて漏らす。
_RAW_TEXT_TAGS = frozenset("noscript iframe xmp noembed noframes textarea title".split())
_IGNORE_END = frozenset({"body", "html"})  # 仕様上、これらの終了タグは以降の本文を閉じない（隠れた要素を道連れに閉じない）
_MOUNT_IDS = frozenset({"root", "app", "__next", "__nuxt", "___gatsby", "q-app", "svelte", "react-root", "main-app", "app-root"})
_JSON_SCRIPT = re.compile(r"json", re.I)
_NON_TEXT_META = frozenset(
    {"viewport", "theme-color", "format-detection", "robots", "referrer", "color-scheme", "generator", "msapplication-tilecolor", "charset"}
)
_ATTR_TEXT = frozenset(
    {"alt", "title", "aria-label", "aria-description", "aria-roledescription", "aria-placeholder", "placeholder", "srcdoc", "abbr", "label"}
)
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
# 異体字セレクタ（U+FE00-FE0F・U+E0100-E01EF）の連なり。256種で1バイトずつ不可視のまま運べる。孤立した1〜2個は
# 字形指定（人名の異体字・絵文字）として正当に使われるので残し、3個以上の連なりだけをデコードして隠しチャネルへ移す。
_VS_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{3,}")
# 人の目に見えず、Cf（textsafe が除く）でもない文字。注入文の語を割ったり空白の代わりに挟んだりする細工に使える。
#   幅を持たない（結合書記素ジョイナ・クメールの固有母音・モンゴル語の自由変化選択子）→ 無いものとして除く
#   空白の幅を持つ塗りつぶし（ハングル充填・点字の空白・物体置換）→ 人にも空白に見えるので空白に直す
_FILLER_TABLE = {ord(c): None for c in "\u034f\u17b4\u17b5\u180b\u180c\u180d\u180f"}
_FILLER_TABLE.update({ord(c): " " for c in "\u115f\u1160\u2800\u3164\uffa0\ufffc"})
_WS = re.compile(r"\s+")
_HTML_LIKE = re.compile(r"<[a-zA-Z][^<>]{0,300}>")
_KIND_ORDER = list(HiddenKind)
# 要素スタックを遡る最大の深さ。深い入れ子を悪用した二乗時間（1MiB で数分）を防ぐ。遡れなければ
# 「閉じない」側（終了タグは無視＝隠す側）に倒れるので、可視への漏れにはならない。
_SCAN_CAP = 128


# --- リンクの判定 ---------------------------------------------------------------------------------------
_LOGIN_LAST = frozenset(
    {"login", "log-in", "log_in", "logon", "signin", "sign-in", "sign_in", "signon", "sign-on", "sso", "saml", "saml2", "authorize"}
)
_LOGIN_HOST_FIRST = frozenset({"login", "signin", "sso", "idp", "accounts", "auth"})


def href_looks_like_login(url: str) -> bool:
    """URL がログイン画面らしいか（パス・ホストの規則）。Reader の role=login 申告を採用する前の裏取り（§3 AUTORUN）。

    保守的に判定する（「/docs/auth」のような説明ページをログインにしない）。最終パス区間がログイン語、
    または先頭ホストラベルが login/signin/sso/idp/accounts/auth のものだけ。
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if host and host.split(".")[0] in _LOGIN_HOST_FIRST:
        return True
    segs = [s for s in parts.path.lower().split("/") if s]
    if not segs:
        return False
    last = segs[-1].rsplit(".", 1)[0]
    if last in _LOGIN_LAST:
        return True
    return len(segs) >= 2 and segs[-2] in ("session", "sessions") and last == "new"


# 案内ページらしいパス区間（辿る価値があるリンクの目印）。役割 docs を付けるのはコードで、モデルの申告は要らない
_DOCS_SEGMENTS = frozenset(
    {"docs", "doc", "guide", "guides", "help", "manual", "usage", "howto", "how-to", "tutorial", "readme", "faq", "wiki",
     "getting-started", "gettingstarted", "support"}
)  # fmt: skip


def href_looks_like_docs(url: str) -> bool:
    """URL が案内ページらしいか（パスの区間が docs・guide・help 等）。リンク表の役割 docs をコードが付ける規則。

    ログインらしい URL は login が先（href_looks_like_login）。docs を付けるのは提出物（role=submission）の文書のリンクだけ
    （要項側の「よくある質問」への案内を、提出物の案内ページと取り違えて辿らないため。要項側のリンクの役割は Reader の提案）。
    ここで付けた docs は「辿る価値がある」という目印にすぎず、
    検査を減らす方向には使わない（contains_terms の結論を、案内ページを辿る前に確定させない側にだけ働く。checks/autorun.py）。
    """
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return any(seg.rsplit(".", 1)[0] in _DOCS_SEGMENTS for seg in path.split("/") if seg)


def link_in_scope(href: str, scope: Sequence[UrlPrefix]) -> bool:
    """絶対URLが取得スコープに入るか。取得時の検査（SafeFetch）と同じ定義を使う（validate_url → スコープ照合）。

    別実装にすると、取得で拒否される URL を「スコープ内」と表示したり（Planner が無駄な取得を選ぶ）、
    取得できる日本語のパス（%XX）を弾いたりする食い違いが出る（統合時に実測）。DNS・IP の検査は取得時に行う。
    """
    try:
        return in_scope(validate_url(href), scope)
    except UrlRejected:
        return False


def _is_exec_script(type_attr: str) -> bool:
    t = type_attr.strip().lower()
    return t in ("", "module") or "javascript" in t or "ecmascript" in t or t == "text/jscript"


# --- 出力の集計 -----------------------------------------------------------------------------------------
class _Collector:
    """複数の HTML 断片（本文＋JSON 内の HTML 文字列）をまたいで、可視ブロック・隠しテキスト・リンクを貯める。"""

    def __init__(self) -> None:
        self.blocks: list[str] = []
        self._cur: list[str] = []
        self.hidden: dict[HiddenKind, list[str]] = {}
        self.links: list[tuple[str, str]] = []
        self.has_password = False
        self.script_count = 0
        self.has_mount = False
        self.has_noscript = False
        self.json_scripts: list[str] = []
        self.base_href: str | None = None

    def _split_tag_chars(self, text: str) -> str:
        """Unicode タグ文字（U+E0000-E007F）と異体字セレクタの連なり（どちらも ASCII/バイトを不可視で運べる）を取り除き、
        デコードした文字列を隠しチャネルへ入れる。"""
        if _TAG_CHARS.search(text):
            payload = "".join(chr(ord(c) - 0xE0000) for c in _TAG_CHARS.findall(text) if 0x20 <= ord(c) - 0xE0000 <= 0x7E)
            if payload:
                self.hidden.setdefault(HiddenKind.UNICODE_TAG, []).append(payload)
            text = _TAG_CHARS.sub("", text)
        if _VS_RUN.search(text):
            for m in _VS_RUN.finditer(text):
                raw = bytes((o - 0xFE00) if o <= 0xFE0F else (o - 0xE0100 + 16) for o in map(ord, m.group()))
                payload = "".join(ch for ch in raw.decode("utf-8", "replace") if ch.isprintable())
                if payload.strip():
                    self.hidden.setdefault(HiddenKind.UNICODE_TAG, []).append(payload)
            text = _VS_RUN.sub("", text)
        return text

    def add_hidden(self, kind: HiddenKind, text: str) -> None:
        text = self._split_tag_chars(text.replace(BLOCK_SEP, " "))
        if text.strip():
            self.hidden.setdefault(kind, []).append(text)

    def add_visible(self, text: str) -> str:
        """可視テキストを現在のブロックへ足す。タグ文字は可視から外す。戻り値は足した文字列。"""
        text = self._split_tag_chars(text.replace(BLOCK_SEP, " "))
        self._cur.append(text)
        return text

    def brk(self) -> None:
        if self._cur:
            s = clean_inline("".join(self._cur))
            self._cur = []
            if s:
                self.blocks.append(s)


def clean_inline(s: str) -> str:
    """空白を畳み、ゼロ幅・bidi・制御文字・不可視の塗りつぶし文字を除く（NBSP・全角空白・点字の空白は空白に）。"""
    s = _WS.sub(" ", s)
    s = strip_unsafe(s).translate(_FILLER_TABLE)
    return _WS.sub(" ", s).strip(" ")


@dataclass
class _Frame:
    tag: str
    hidden: frozenset[HiddenKind]
    is_anchor: bool = False
    is_pre: bool = False
    is_foreign: bool = False
    is_svg_math: bool = False  # <svg>/<math>（foreign と同じ。文字の描画場所の判定用）
    text_ok: bool = False  # SVG/MathML の中で、文字が描画される要素
    foreign_el: bool = False  # SVG/MathML 名前空間の要素（HTML の暗黙の終了・書式要素の再開の対象外）
    saved_text_ok: int = 0  # <svg>/<math> の根で、外側の text_ok の数を退避する（根ごとに数え直す）
    afe: "_AfeEntry | None" = None  # 書式要素の再開リストの項目（隠す指定を持つ書式要素だけ）
    marker: bool = False  # 再開の境界になる要素（td・th・caption・template・object・applet・marquee）
    is_script: bool = False
    attrs_id: str = ""
    script_type: str = ""


class _AfeEntry:
    """再開リストの1項目。tag と、その要素が自身で持つ「隠す」種別。frame は今スタックにある要素（閉じられたら None）。"""

    __slots__ = ("tag", "own", "frame")

    def __init__(self, tag: str, own: frozenset[HiddenKind], frame: "_Frame | None") -> None:
        self.tag = tag
        self.own = own
        self.frame = frame


@dataclass(frozen=True)
class _Ctx:
    """文書全体に効く前提（1回目の走査で集める）。"""

    root_kinds: frozenset[HiddenKind] = frozenset()  # <html>/<body> の隠し指定。2つ目以降の開始タグも含む
    rules: css_hide.StyleRules | None = None  # 同じ文書の <style> にある単純な規則（submission だけ）


_MULTI_ATTRS = frozenset({"style", "hidden", "aria-hidden", "type", "popover"})
_SVG_TEXT_TAGS = frozenset({"text", "tspan", "textpath"})
# SVG で、子の文字まで描画が届く要素。これ以外（<td>・<nav>・<cite> など SVG に無い名前の要素）は、描画の対象にならず、
# その子孫は（入れ子の <svg>・<text> でも）描画されない。
_SVG_RENDER_CONTAINERS = frozenset({"svg", "g", "a", "switch", "text", "tspan", "textpath", "foreignobject"})


def _split_attrs(pairs: list[tuple[str, str | None]]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """属性を (最初の値, 隠しに関わる属性の全ての値) に分ける。ブラウザは同名の属性が重なると最初のものだけを使うが、
    隠しの判定は重なった全部のどれか1つでも隠していれば隠す（後ろへ打ち消す属性を足す細工の対策）。"""
    first: dict[str, str] = {}
    multi: dict[str, list[str]] = {}
    for k, v in pairs:
        v = "" if v is None else v
        if k not in first:
            first[k] = v
        if k in _MULTI_ATTRS:
            multi.setdefault(k, []).append(v)
    return first, multi


def _own_kinds(
    tag: str, attrs: dict[str, str], multi: dict[str, list[str]], *, foreign: bool, visible_kinds: frozenset[HiddenKind], svg_unknown: bool = False
) -> set[HiddenKind]:
    """要素自身が持つ「隠す」指定の種別（祖先から引き継ぐ分は含まない）。svg_unknown は、SVG の中の SVG に無い名前の外来要素。"""
    own: set[HiddenKind] = set()
    if svg_unknown:
        own.add(HiddenKind.OTHER)
    if tag in _HIDDEN_TAGS:
        own.add(HiddenKind.OTHER)
    if "hidden" in attrs or "popover" in attrs:  # popover は開くまで display:none（UA の既定）
        own.add(HiddenKind.HIDDEN_ATTR)
    if any(v.strip().lower() == "true" for v in multi.get("aria-hidden", ())):
        own.add(HiddenKind.ARIA_HIDDEN)
    if tag == "dialog" and "open" not in attrs:
        own.add(HiddenKind.HIDDEN_ATTR)
    if tag == "input" and any(v.strip().lower() == "hidden" for v in multi.get("type", ())):
        own.add(HiddenKind.INPUT_HIDDEN)
    for st in multi.get("style", ()):
        own |= css_hide.hidden_kinds_from_style(st)
    if foreign:
        # SVG/MathML では display・visibility・opacity などが属性でも書ける（プレゼンテーション属性）
        decls = [
            (("opacity" if k == "fill-opacity" else k), attrs[k].strip().lower())
            for k in ("display", "visibility", "opacity", "fill-opacity", "font-size", "transform", "clip-path")
            if k in attrs
        ]
        if decls:
            own |= css_hide.kinds_from_declarations(decls)
        if tag in _SVG_TEXT_TAGS and attrs.get("fill", "").strip().lower() in ("none", "transparent") and attrs.get("stroke", "none").strip().lower() in ("none", ""):
            own.add(HiddenKind.CSS_OPACITY_ZERO)
        # 大きさ・位置で見えなくする: <svg> の外へ出る文字・大きさゼロの <svg>/<foreignObject>（既定の幅・高さは 0）
        if tag in _SVG_TEXT_TAGS and any(_svg_far(attrs.get(k, "")) for k in ("x", "y", "dx", "dy")):
            own.add(HiddenKind.CSS_OFFSCREEN)
        if tag == "foreignobject" and not (_svg_roomy(attrs.get("width", "")) and _svg_roomy(attrs.get("height", ""))):
            own.add(HiddenKind.CSS_OFFSCREEN)  # 幅・高さの既定は 0。1px 以下の箱も、中の文字は切り抜かれて読めない
        if tag == "svg" and any(_svg_tiny(attrs.get(k, "")) for k in ("width", "height")):
            own.add(HiddenKind.CSS_OFFSCREEN)
    return own - (visible_kinds - {HiddenKind.OTHER})


_SVG_NUM = re.compile(r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))")


def _svg_first_number(v: str) -> float | None:
    m = _SVG_NUM.match(v)
    return float(m.group(1)) if m else None


def _svg_far(v: str) -> bool:
    """x・y・dx・dy の座標のどれかが、<svg> の外へ飛ばす大きさか（先頭の数だけを見る。数列の2つ目以降も見る）。"""
    return any(abs(float(n)) >= 5000 for n in re.findall(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", v))


def _svg_positive(v: str) -> bool:
    n = _svg_first_number(v)
    return n is not None and n > 0


def _svg_roomy(v: str) -> bool:
    n = _svg_first_number(v)
    return n is not None and (n > 1 or v.strip().endswith("%") and n > 0)


def _svg_tiny(v: str) -> bool:
    n = _svg_first_number(v)
    return n is not None and n <= 1 and not v.strip().endswith("%")


# <script> のデータ状態（HTML 仕様の「エスケープ」「二重エスケープ」）。二重エスケープの中では </script> は終了タグにならない。
_SCRIPT_TOKEN = re.compile(r"<!--(-*>)?|-->|<script(?=[\t\n\f\r />])|</script(?=[\t\n\f\r />])", re.I)


def _script_scan(text: str, state: int) -> int:
    """state: 0=通常 1=エスケープ（<!-- の後） 2=二重エスケープ（その中の <script の後）。text を読んだ後の状態を返す。"""
    for m in _SCRIPT_TOKEN.finditer(text):
        tok = m.group().lower()
        if tok.startswith("<!--"):
            closed = bool(m.group(1))  # "<!-->" "<!--->" はコメントがその場で閉じる
            if state == 0:
                state = 0 if closed else 1
            elif closed:
                state = 0
        elif tok == "-->":
            if state:
                state = 0
        elif tok == "<script":
            if state == 1:
                state = 2
        elif state == 2:  # </script
            state = 1
    return state


class _TokenizerBase(HTMLParser):
    """html.parser の字句解析を、ブラウザの規則に合わせる土台（本走査と1回目の走査で共有する）。

    トークンの切り方が本走査と1回目の走査でずれると、1回目が見落とした開始タグ（<body style=…>）で文書全体の隠しを
    取りこぼす。字句の規則はここ1か所に置く。
      * "<!-->" と "<!--->" はその場で閉じる空のコメント（html.parser は後ろの "-->" を先に探して本文を飲み込む）
      * <script> の二重エスケープ（<!-- … <script> … </script> … </script>）の内側の </script> は終了タグでない
      * noscript・iframe・xmp などは版によらず生テキストモード。ただし SVG/MathML の中の script/style/title など
        は外来要素で、中身は普通のマークアップ
    """

    def __init__(self, *, convert_charrefs: bool) -> None:
        super().__init__(convert_charrefs=convert_charrefs)
        self._script_state = 0
        self._script_open = False
        self._keep_raw = False  # 直後の clear_cdata_mode を打ち消す（二重エスケープの内側の </script>）

    # --- 外来コンテキストの判定（サブクラスが実装） ---------------------------------------------------
    def _raw_suppressed(self, elem: str) -> bool:
        return False

    def _append_script_text(self, text: str) -> None:
        """二重エスケープの中で終了タグを文字として取り込む（本走査はスクリプトの本文にも足す）。"""

    # --- 字句の規則 -----------------------------------------------------------------------------
    def set_cdata_mode(self, elem: str, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        if self._raw_suppressed(elem):
            return  # 外来要素（<svg><script>・<math><style>）は生テキストにならない
        super().set_cdata_mode(elem, *args, **kwargs)  # type: ignore[arg-type]

    def clear_cdata_mode(self) -> None:
        # html.parser は終了タグを handle_endtag へ渡した直後にこれを呼ぶ。二重エスケープの内側の </script> では、
        # 生テキストモードのまま続けたい（続く < … > をタグとして解析させない）ので、1回だけ打ち消す。
        if self._keep_raw:
            self._keep_raw = False
            return
        super().clear_cdata_mode()

    def parse_comment(self, i: int, report: bool = True) -> int:  # type: ignore[override]
        raw = self.rawdata
        if raw.startswith(">", i + 4) or raw.startswith("->", i + 4):
            if report:
                self.handle_comment("")
            return i + (5 if raw[i + 4] == ">" else 6)
        return super().parse_comment(i, report)  # type: ignore[misc]

    def _enter_raw(self, tag: str, *, selfclosing: bool, foreign: bool) -> None:
        """開始タグの直後に呼ぶ。生テキスト（RCDATA を含む）の要素なら、版によらずそのモードへ入れる。"""
        if foreign:
            return
        if tag in ("script", "style") or tag in _RAW_TEXT_TAGS:
            if selfclosing or self.cdata_elem is None:
                self.set_cdata_mode(tag)
        if tag == "script" and self.cdata_elem == "script":
            self._script_open = True
            self._script_state = 0

    def _note_data(self, data: str) -> None:
        if self._script_open:
            self._script_state = _script_scan(data, self._script_state)

    def _swallow_script_end(self, tag: str) -> bool:
        """</script> が二重エスケープの内側なら、終了タグとして扱わず生テキストへ戻す。"""
        if tag != "script" or not self._script_open:
            return False
        if self._script_state == 2:
            self._script_state = _script_scan("</script>", 2)
            self._append_script_text("</script>")
            self._keep_raw = True
            return True
        self._script_open = False
        return False


class _ProbeParser(_TokenizerBase):
    """1回目の走査。文書全体に効く情報だけを集める（本文は見ない）:
      * <html>/<body> の隠し指定。ブラウザは2つ目以降の <body>/<html> 開始タグを「既存の要素へ属性を足す」だけで扱うので、
        <p>注入文</p><body style="display:none"> のように、後ろに置いた指定が先の本文も隠す。
      * <style> の本文（style_rules のとき）。クラスで隠す細工は、規則が文書の後ろにあっても効く。"""

    def __init__(self, visible_kinds: frozenset[HiddenKind], *, want_styles: bool) -> None:
        super().__init__(convert_charrefs=False)
        self.visible_kinds = visible_kinds
        self.want_styles = want_styles
        self.root_kinds: set[HiddenKind] = set()
        self.root_tags: list[tuple[str, list[str], str]] = []  # (tag, class, id)。規則（クラス）を後で当てる
        self.styles: list[str] = []
        self._style_buf: list[str] | None = None
        self._style_chars = 0
        self._fdepth = 0  # 開いている <svg>/<math> の数（近似）
        self._fint = 0  # その中の HTML 統合点（foreignObject など）の数

    def _raw_suppressed(self, elem: str) -> bool:
        return self._fdepth > 0 and self._fint == 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, selfclosing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, selfclosing=True)

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], *, selfclosing: bool) -> None:
        foreign = self._fdepth > 0 and self._fint == 0
        if foreign and tag in _FOREIGN_BREAKOUT:
            self._fdepth = self._fint = 0  # HTML の「抜け出し」タグは SVG/MathML を閉じて HTML に戻る
            foreign = False
        if tag in ("html", "body") and not foreign:
            a, multi = _split_attrs(attrs)
            self.root_kinds |= _own_kinds(tag, a, multi, foreign=False, visible_kinds=self.visible_kinds)
            self.root_tags.append((tag, a.get("class", "").split(), a.get("id", "")))
        elif tag == "style" and self.want_styles and not selfclosing:  # SVG の <style> も文書全体に効く
            media = dict(attrs).get("media") or ""
            if media.strip().lower() in ("", "all", "screen"):
                self._style_buf = []
        if tag in ("svg", "math") and not selfclosing:
            self._fdepth += 1
        elif self._fdepth and tag in _FOREIGN_INTEGRATION and not selfclosing:
            self._fint += 1
        self._enter_raw(tag, selfclosing=selfclosing, foreign=foreign)

    def handle_data(self, data: str) -> None:
        self._note_data(data)
        if self._style_buf is not None and self._style_chars < MAX_STYLE_CHARS:
            self._style_buf.append(data)
            self._style_chars += len(data)

    def handle_endtag(self, tag: str) -> None:
        if self._swallow_script_end(tag):
            return
        if tag == "style" and self._style_buf is not None:
            self.styles.append("".join(self._style_buf))
            self._style_buf = None
        elif tag in ("svg", "math") and self._fdepth:
            self._fdepth -= 1
            if not self._fdepth:
                self._fint = 0
        elif self._fint and tag in _FOREIGN_INTEGRATION:
            self._fint -= 1


def _probe(html: str, visible_kinds: frozenset[HiddenKind], *, want_styles: bool) -> _Ctx:
    """文書全体に効く指定を集める。壊れた入力でも例外にしない（集められなければ空の前提）。"""
    p = _ProbeParser(visible_kinds, want_styles=want_styles)
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001  パーサの想定外の例外は、前提なしで続ける（本走査は別に走る）
        pass
    rules = None
    root = set(p.root_kinds)
    if want_styles and p.styles:
        rules = css_hide.StyleRules(transparent=not any(css_hide.CLIP_TEXT.search(css) for css in p.styles))
        for css in p.styles:
            rules.add_css(css)
        for tag, classes, ident in p.root_tags:  # <body class="x"> に .x{display:none} が掛かる細工
            root |= rules.kinds_for(tag, classes, ident) - (p.visible_kinds - {HiddenKind.OTHER})
    return _Ctx(frozenset(root), rules if rules else None)


class _HtmlParser(_TokenizerBase):
    """要素スタックを持ち、可視／隠しを振り分ける。1断片につき1インスタンス。"""

    def __init__(self, out: _Collector, visible_kinds: frozenset[HiddenKind], ctx: _Ctx = _Ctx()) -> None:
        super().__init__(convert_charrefs=True)
        self.out = out
        self.visible_kinds = visible_kinds
        self.ctx = ctx
        self.frames: list[_Frame] = []
        self._open_count: dict[str, int] = {}
        self._pre = 0
        self._foreign = 0
        self._text_ok = 0  # SVG/MathML の中の、文字が描画される祖先の数
        self._roots: list[str] = []  # 開いている <svg>/<math> の根（一番内側が末尾）
        self._afe: list[_AfeEntry | None] = []  # None は境界（marker）
        self._script_buf: list[str] | None = None
        self._script_state = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    # --- 状態 -----------------------------------------------------------------------------------
    def _cur_hidden(self) -> frozenset[HiddenKind]:
        return self.frames[-1].hidden if self.frames else self.ctx.root_kinds

    @staticmethod
    def _pick(kinds: frozenset[HiddenKind]) -> HiddenKind:
        for k in _KIND_ORDER:
            if k in kinds:
                return k
        return HiddenKind.OTHER

    def _own_hidden(
        self, tag: str, attrs: dict[str, str], multi: dict[str, list[str]], *, foreign_el: bool = False, cross_root: bool = False
    ) -> set[HiddenKind]:
        svg_unknown = cross_root or (foreign_el and tag not in ("svg", "math") and self._roots[-1:] == ["svg"] and tag not in _SVG_RENDER_CONTAINERS)
        own = _own_kinds(tag, attrs, multi, foreign=self._foreign > 0 or tag in ("svg", "math"), visible_kinds=self.visible_kinds, svg_unknown=svg_unknown)
        if tag in ("option", "optgroup") and not self._open_count.get("select"):
            own.add(HiddenKind.OTHER)  # <select> の外の <option> は描画されない（Chromium）
        if self.ctx.rules is not None:
            found = self.ctx.rules.kinds_for(tag, attrs.get("class", "").split(), attrs.get("id", ""))
            own |= found - (self.visible_kinds - {HiddenKind.OTHER})
        return own

    # --- テキスト -------------------------------------------------------------------------------
    def _raw_suppressed(self, elem: str) -> bool:
        # html.parser は開始タグの処理の後でこれを呼ぶ。今の要素（直前に開いた script など）が外来要素なら生テキストにしない
        return bool(self.frames) and self.frames[-1].tag == elem and self.frames[-1].foreign_el

    def _append_script_text(self, text: str) -> None:
        if self._script_buf is not None:
            self._script_buf.append(text)

    def handle_data(self, data: str) -> None:
        self._note_data(data)
        if self._script_buf is not None:
            self._script_buf.append(data)
            return
        if self.cdata_elem is None:
            self._reconstruct()
        kinds = self._cur_hidden()
        if not kinds and self._open_count.get("select") and not self._open_count.get("option"):
            kinds = frozenset({HiddenKind.OTHER})  # <select> の中で <option> の外にある文字は描画されない
        if not kinds and self._foreign and not self._text_ok:
            kinds = frozenset({HiddenKind.OTHER})  # <svg>/<math> の直下など、文字が描画されない場所
        if kinds:
            self.out.add_hidden(self._pick(kinds), data)
            return
        if self._pre and "\n" in data:
            lines = data.split("\n")
            for i, line in enumerate(lines):
                if i:
                    self._brk()
                self._visible(line)
            return
        self._visible(data)

    def _visible(self, text: str) -> None:
        added = self.out.add_visible(text)
        if self._anchor_href is not None:
            self._anchor_text.append(added)

    def _brk(self) -> None:
        self.out.brk()

    def handle_comment(self, data: str) -> None:
        self.out.add_hidden(HiddenKind.OTHER, data)

    def handle_pi(self, data: str) -> None:
        self.out.add_hidden(HiddenKind.OTHER, data)

    def unknown_decl(self, data: str) -> None:
        self.out.add_hidden(HiddenKind.OTHER, data)

    # --- 開始タグ -------------------------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a, multi = _split_attrs(attrs)
        self._open(tag, a, multi)
        self._enter_raw(tag, selfclosing=False, foreign=bool(self.frames) and self.frames[-1].tag == tag and self.frames[-1].foreign_el)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # HTML 要素の「/>」は無視される（開始タグとして扱う）。ブラウザは <div style="display:none"/> 以降を隠す。
        # 外来要素（SVG/MathML の中の、抜け出しタグ以外）だけは「/>」で閉じる。
        a, multi = _split_attrs(attrs)
        foreign = tag in ("svg", "math") or self._in_foreign()
        self._open(tag, a, multi)
        if foreign and tag not in _VOID and tag not in _FOREIGN_BREAKOUT:
            self._close(tag)
        else:
            self._enter_raw(tag, selfclosing=True, foreign=False)

    def _pop_to(self, targets: frozenset[str] | set[str], stop: frozenset[str] | set[str]) -> None:
        """スタックを上から辿り、stop に当たる前に targets の要素があれば、それまでを閉じる。"""
        if not any(self._open_count.get(t) for t in targets):
            return
        low = max(0, len(self.frames) - _SCAN_CAP)
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t in targets:
                self._pop_closing_cells(i)
                return
            if t in stop or t in ("select", "template") or (self.frames[i].foreign_el and t in _FOREIGN_INTEGRATION):
                return  # <select> の中ではブラウザは他の要素の開始・終了を無視する。<template>・HTML 統合点の中身は別の文脈（外側の要素を閉じない）

    def _pop_list_item(self, targets: frozenset[str] | set[str]) -> None:
        """<li>/<dd>/<dt> の暗黙の終了（HTML 仕様どおり）: 上から辿り、同種の要素に当たれば閉じ、address/div/p 以外の
        special 要素に当たれば閉じずに止める（その中で始まった li は隠れた li の子になる＝隠れたまま）。"""
        if not any(self._open_count.get(t) for t in targets):
            return
        low = max(0, len(self.frames) - _SCAN_CAP)
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t in targets:
                self._pop_frames(i)
                return
            if t in _HTML_SPECIAL and t not in _LI_EXEMPT:
                return

    def _implied_close(self, tag: str) -> None:
        if tag == "li":
            self._pop_list_item({"li"})
        elif tag in ("dt", "dd"):
            self._pop_list_item({"dt", "dd"})
        elif tag in ("td", "th"):
            self._pop_to({"td", "th"}, {"tr", "table"})
        elif tag == "tr":  # 行を閉じる（開いていなければ、セルだけを閉じる）
            self._pop_to({"tr"}, {"table"})
            self._pop_to({"td", "th"}, {"tr", "table"})
        elif tag in ("thead", "tbody", "tfoot", "caption"):  # 区画を閉じる（無ければ行、無ければセル。外側の表へは出ない）
            self._pop_to({"thead", "tbody", "tfoot", "caption"}, {"table"})
            self._pop_to({"tr"}, {"table"})
            self._pop_to({"td", "th"}, {"tr", "table"})
        elif tag in ("rb", "rt", "rp", "rtc") and self._open_count.get("ruby"):
            # <ruby> の中で rb/rt/rp/rtc が始まると、「暗黙の終了タグ」（p・li・dd・dt・option・optgroup・rb・rp・rt・rtc）を閉じる。
            # <p> の中の <rp> でも先に <p> が閉じ、続く <hr> などが隠れた rp を巻き込んで閉じない
            keep = frozenset({"dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt"}) | ({"rtc"} if tag in ("rb", "rtc") else frozenset())
            while self.frames and self.frames[-1].tag in keep:
                self._pop_frames(len(self.frames) - 1)
        elif tag in ("option", "optgroup"):
            # 仕様: 今の要素（スタックの先頭）が option のときだけ閉じる（<select> の中の optgroup は、続けて optgroup も閉じる）。
            # 奥にある option まで遡って閉じると、間の要素の中で始まった option が、隠れた option の子にならず可視へ漏れる。
            top = self.frames[-1].tag if self.frames else ""
            if top == "option":
                self._pop_frames(len(self.frames) - 1)
                top = self.frames[-1].tag if self.frames else ""
            if tag == "optgroup" and top == "optgroup" and self._open_count.get("select"):
                self._pop_frames(len(self.frames) - 1)
        if tag in _P_CLOSERS:
            self._pop_to({"p"}, _SCOPE_STOP | {"button"})

    # --- 書式要素の再開（active formatting elements） -------------------------------------------------
    def _afe_add(self, entry: _AfeEntry, frame: _Frame) -> None:
        """隠す指定を持つ書式要素を再開リストへ入れる。仕様の「同じものは3つまで」（Noah's Ark）で長さを抑える。"""
        frame.afe = entry
        count = 0
        for i in range(len(self._afe) - 1, -1, -1):
            e = self._afe[i]
            if e is None:
                break
            if e.tag == entry.tag and e.own == entry.own:
                count += 1
                if count >= 3:
                    del self._afe[i]
                    break
        self._afe.append(entry)

    def _afe_clear_to_marker(self) -> None:
        while self._afe:
            if self._afe.pop() is None:
                break

    def _afe_remove(self, tag: str) -> None:
        """終了タグ（</b> など）で、その書式要素を再開リストから外す。"""
        for i in range(len(self._afe) - 1, -1, -1):
            e = self._afe[i]
            if e is None:
                return
            if e.tag == tag:
                del self._afe[i]
                return

    def _reconstruct(self) -> None:
        """閉じられた隠す書式要素を、続く文字・開始タグの前に再び開く（クローンは同じ隠す指定を持つ）。"""
        afe = self._afe
        if not afe or afe[-1] is None or afe[-1].frame is not None:  # type: ignore[union-attr]
            return
        i = len(afe) - 1
        while i > 0 and afe[i - 1] is not None and afe[i - 1].frame is None:  # type: ignore[union-attr]
            i -= 1
        for j in range(i, len(afe)):
            e = afe[j]
            if e is None or e.frame is not None:
                continue
            frame = _Frame(e.tag, self._cur_hidden() | e.own)
            frame.afe = e
            e.frame = frame
            self.frames.append(frame)
            self._open_count[e.tag] = self._open_count.get(e.tag, 0) + 1

    def _close_table_for_new_table(self) -> None:
        """表（行・区画・表の直下）の中で <table> が始まると、仕様は開いている表を閉じてから新しい表を始める（入れ子にならない）。
        セル・キャプション・template の中なら、そこへ入れ子になる。閉じないと、続く表の要素（<td> など）が古い表のセルとして扱われ、
        手前の隠れた要素を巻き戻しで閉じてしまう。"""
        low = max(0, len(self.frames) - _SCAN_CAP)
        near = None
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t in ("td", "th", "caption", "template"):
                return
            if t in ("tr", "tbody", "thead", "tfoot", "table"):
                near = i
                break
        if near is None:
            return
        for i in range(near, low - 1, -1):
            if self.frames[i].tag == "table":
                self._pop_frames(i)
                return

    def _close_sections_for_columns(self) -> None:
        """表の区画・行の中で <col>・<colgroup> が始まると、仕様は行・区画を閉じて「表の直下」へ戻してから列グループを作る
        （続く </tbody> は無視される）。巻き戻さないと、続く </tbody> が、間にあるフォスター親化された隠れた要素ごと閉じてしまう。"""
        low = max(0, len(self.frames) - _SCAN_CAP)
        near = None
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t in ("td", "th", "caption", "template"):
                return
            if t in ("tr", "tbody", "thead", "tfoot", "table"):
                near = t
                break
        if near in (None, "table"):
            return
        for i in range(len(self.frames) - 1, low - 1, -1):
            if self.frames[i].tag == "table":
                if i + 1 < len(self.frames):
                    self._pop_closing_cells(i + 1)
                return

    def _clear_back_to_table_context(self) -> None:
        """表の区画・行・表の直下（「テーブル」「テーブル本体」「行」の各モード）で表の要素が始まったとき、仕様は「表の文脈まで
        スタックを巻き戻す」: 表の構造の要素（table・tbody・thead・tfoot・tr）の上に、フォスター親化で積まれた別の要素
        （<footer>・<a> など）があれば閉じる。巻き戻さないと、続く文字を、閉じられたはずの隠れた要素の子にしてしまう。"""
        low = max(0, len(self.frames) - _SCAN_CAP)
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t in ("td", "th", "template"):
                return  # セルの中（in cell）・template の中身は、本文と同じ規則（別の文脈）
            if t in ("tr", "tbody", "thead", "tfoot", "table"):
                # キャプションの中で表の要素が始まったときも、ここに来て（キャプションを含めて）表の直下まで巻き戻す
                if i + 1 < len(self.frames):
                    self._pop_closing_cells(i + 1)
                return

    def _close_open_anchor(self) -> None:
        """<a> の中で <a> が始まったら前の <a> を閉じる。間にブロック要素があれば、ブロックは開いたまま <a> だけ外す
        （仕様の adoption agency の近似。ブロックごと閉じると、その中の隠れ要素の子が可視へ漏れる）。"""
        if not self._open_count.get("a"):
            return
        low = max(0, len(self.frames) - _SCAN_CAP)
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t == "a":
                entry = self.frames[i].afe
                if any(f.tag in _SPECIAL for f in self.frames[i + 1 :]):
                    f = self.frames.pop(i)
                    self._open_count["a"] -= 1
                    self._finalize(f)
                else:
                    self._pop_frames(i)
                if entry is not None and entry in self._afe:
                    self._afe.remove(entry)  # <a> の中の <a> は、前の <a> を再開リストからも外す（仕様）
                return
            if t in _SCOPE_STOP or t in ("button", "select"):
                return

    def _in_foreign(self) -> bool:
        """今の要素が SVG/MathML の要素（HTML 統合点でない）か。その子は、抜け出しタグ以外は外来要素になる。"""
        if not self._foreign or not self.frames:
            return False
        f = self.frames[-1]
        return f.foreign_el and f.tag not in _FOREIGN_INTEGRATION

    def _open(self, tag: str, attrs: dict[str, str], multi: dict[str, list[str]]) -> None:
        out = self.out
        if (
            self.frames
            and self.frames[-1].tag in ("select", "option", "optgroup")
            and not self.frames[-1].foreign_el
            and tag not in _SELECT_KEEPS
            and self._open_count.get("select")
        ):
            return  # <select> の中（select モード）の他の開始タグは無視される（要素にならない。Chromium で実測）
        foreign_ctx = self._in_foreign()
        if foreign_ctx and (tag in _FOREIGN_BREAKOUT or (tag == "font" and ("color" in attrs or "face" in attrs or "size" in attrs))):
            # HTML の「抜け出し」タグ: 仕様は、HTML 要素か HTML 統合点に当たるまで外来要素（SVG/MathML）を閉じてから、HTML として処理する。
            # 閉じないでおくと、後ろの </svg> が、抜け出した後に開いた HTML 要素（隠れた <canvas> など）を道連れに閉じてしまう。
            while self.frames and self.frames[-1].foreign_el and self.frames[-1].tag not in _FOREIGN_INTEGRATION:
                self._pop_frames(len(self.frames) - 1)
            foreign_ctx = self._in_foreign()
        # <svg> の中の <math>（と、その逆）は、外側の名前空間の「知らない名前の要素」になる（新しい根ではない）
        cross_root = tag in ("svg", "math") and foreign_ctx and bool(self._roots) and self._roots[-1] != tag
        root_tag = tag in ("svg", "math") and not cross_root
        foreign_el = root_tag or (foreign_ctx and tag not in _FOREIGN_BREAKOUT)
        if tag in _TABLE_ONLY and not self._open_count.get("table") and not foreign_el:
            # 表の外の <td>・<tr>・<tbody> などは、ブラウザが開始タグごと無視する（要素にならず、中の文字は普通の本文）。
            # 要素にして「暗黙の終了」を走らせると、手前に開いている隠れた要素を閉じて、続く文字を可視へ漏らす。
            return
        if self._open_count.get("select") and not foreign_el and tag in _CLOSES_SELECT and self.frames and self.frames[-1].tag in ("select", "option", "optgroup"):
            # <select> の中で input が始まると、<select> を閉じてからそのタグを処理する。続く <option> は select の外になり描画されない
            self._pop_to({"select"}, set())
        if tag == "select" and self._open_count.get("select") and not foreign_el:
            # <select> の中の <select> は、新しい要素にならない。開いている <select> が「select スコープ」（間にあるのが
            # option/optgroup だけ）にあれば閉じ、無ければ無視する（表や div の中なら、外側の select は開いたまま＝隠れたまま）。
            # 閉じた場合、続く <option> は <select> の外になり、描画されない。
            i = len(self.frames) - 1
            while i >= 0 and self.frames[i].tag in ("option", "optgroup"):
                i -= 1
            if i >= 0 and self.frames[i].tag == "select":
                self._pop_frames(i)
            return
        if tag in _TABLE_ONLY and tag != "col" and self._open_count.get("table") and not foreign_el:
            self._clear_back_to_table_context()
        if tag == "table" and self._open_count.get("table") and not foreign_el:
            self._close_table_for_new_table()
        if tag in ("col", "colgroup") and self._open_count.get("table") and not foreign_el:
            self._close_sections_for_columns()
        if foreign_ctx and foreign_el:
            pass  # 外来要素の中の外来要素: HTML の暗黙の終了・書式要素の再開は働かない
        else:
            if tag == "a":
                self._close_open_anchor()
            elif tag in _BLOCK or tag in _RUBY_PARTS:
                self._implied_close(tag)
            if tag not in _NO_RECONSTRUCT:
                self._reconstruct()
        own = self._own_hidden(tag, attrs, multi, foreign_el=foreign_el, cross_root=cross_root)
        parent = self._cur_hidden()
        kinds = parent | own if own else parent

        # 属性値（隠しチャネル）
        typ = attrs.get("type", "").strip().lower()
        for text in self._attr_texts(tag, attrs, typ):
            out.add_hidden(HiddenKind.INPUT_HIDDEN if (tag == "input" and typ == "hidden") else HiddenKind.OTHER, text)

        if attrs.get("id", "") in _MOUNT_IDS:
            out.has_mount = True
        if tag == "noscript":
            out.has_noscript = True
        if tag == "base" and out.base_href is None and attrs.get("href"):
            out.base_href = attrs["href"]
        if tag == "input" and typ == "password" and not kinds:
            out.has_password = True
        if tag == "meta":
            return
        if tag == "br":
            self._brk()
            return
        if tag in _VOID:
            if tag == "hr":
                self._brk()
            return

        frame = _Frame(tag, kinds)
        frame.foreign_el = foreign_el
        if tag in _BLOCK:
            self._brk()
        if tag == "script" and not foreign_el:
            frame.is_script = True
            frame.attrs_id = attrs.get("id", "")
            frame.script_type = attrs.get("type", "")
            if _is_exec_script(frame.script_type):
                out.script_count += 1
            self._script_buf = []
        elif tag == "pre":
            frame.is_pre = True
            self._pre += 1
        elif root_tag:
            frame.is_foreign = True
            frame.is_svg_math = True
            frame.saved_text_ok = self._text_ok
            self._text_ok = 0  # 根ごとに数え直す（抜け出した HTML の中の新しい <math> は、その直下の文字が描画されない）
            self._foreign += 1
            self._roots.append(tag)
        elif tag == "a":
            self._finish_anchor()
            href = attrs.get("href", "").strip()
            if href and not kinds:
                frame.is_anchor = True
                self._anchor_href = href
                self._anchor_text = []
        if self._foreign and tag in _FOREIGN_TEXT_OK and not frame.is_svg_math:
            frame.text_ok = True
            self._text_ok += 1
        if tag in _AFE_MARKERS:
            frame.marker = True
            self._afe.append(None)
        elif tag in _FORMATTING and own:
            self._afe_add(_AfeEntry(tag, frozenset(own), frame), frame)
        self.frames.append(frame)
        self._open_count[tag] = self._open_count.get(tag, 0) + 1

    @staticmethod
    def _attr_texts(tag: str, attrs: dict[str, str], typ: str) -> Iterable[str]:
        for k, v in attrs.items():
            v = v.strip()
            if len(v) < 2:
                continue
            if k in _ATTR_TEXT:
                yield v
            elif k.startswith("data-") and len(v) >= 12 and (" " in v or not v.isascii()):
                yield v
            elif k == "content" and tag == "meta":
                name = (attrs.get("name") or attrs.get("property") or attrs.get("http-equiv") or "").strip().lower()
                if name not in _NON_TEXT_META and not name.startswith(("apple-", "msapplication-")):
                    yield v
            elif k == "value" and tag in ("input", "button", "option", "data") and typ != "password":
                yield v

    # --- 終了タグ -------------------------------------------------------------------------------
    def handle_endtag(self, tag: str) -> None:
        if self._swallow_script_end(tag):  # 二重エスケープの内側の </script> は、スクリプトの文字
            return
        self._close(tag)

    def _close(self, tag: str) -> None:
        if tag in _IGNORE_END or tag in _VOID:
            return
        if tag == "foreignobject" and self._in_foreign():
            return  # <svg> の中の </foreignObject>（HTML 側で開いた foreignobject）は、Chromium では閉じない（隠れたまま）
        if not self._open_count.get(tag):
            if tag in _FORMATTING:
                self._afe_remove(tag)  # 閉じ済みの書式要素の終了タグ。再開リストの項目だけ外す
            return
        if tag == "form" and self.frames and self.frames[-1].tag != "form":
            # </form> は form を開いた要素の一覧から外すだけで、その上に開いている要素は閉じない（それらは DOM では
            # form の子のまま）。閉じてしまうと、form が隠れているときに続く文字が可視へ漏れる。
            return
        if tag in ("td", "th", "tr", "thead", "tbody", "tfoot", "caption"):
            stop: frozenset[str] | set[str] = _TABLE_STOP
        elif tag == "table":
            stop = {"template", "html"}
        elif tag == "p":
            stop = _SCOPE_STOP | {"button"}  # </p> は「button スコープ」: <button> の外の <p> は閉じない
        elif tag == "li":
            stop = _SCOPE_STOP | {"ol", "ul"}  # </li> は「list item スコープ」
        elif tag in _SPECIAL and tag not in _OTHER_END:
            stop = _SCOPE_STOP
        else:
            stop = set()
        low = max(0, len(self.frames) - _SCAN_CAP)
        for i in range(len(self.frames) - 1, low - 1, -1):
            t = self.frames[i].tag
            if t == tag:
                entry = self.frames[i].afe
                self._pop_closing_cells(i)
                if entry is not None and entry in self._afe:
                    self._afe.remove(entry)  # 自分の終了タグで閉じた書式要素は、再び開かれない
                return
            if self.frames[i].foreign_el and t in _FOREIGN_INTEGRATION:
                return  # SVG の <title>・<desc>・<foreignObject> など HTML 統合点の中の終了タグは、その外側の要素を閉じない
            if t == "select" and tag != "select":
                if tag in _TABLE_END and self._open_count.get("table") and any(f.tag == tag for f in self.frames[:i]):
                    # 表の中で作られた <select>（in select in table）は、表の終了タグで閉じてから、その終了タグを処理し直す
                    self._pop_frames(i)
                    self._close(tag)
                return  # それ以外の <select> の中の終了タグは無視される
            if t in stop:
                return  # 範囲外の終了タグは無視（隠れた要素を道連れに閉じない）
            if (tag not in _SPECIAL or tag in _OTHER_END) and t in _HTML_SPECIAL:
                return  # span・option などの終了タグは、間に special 要素があれば無視（仕様の「その他の終了タグ」）

    def _pop_frames(self, index: int) -> None:
        while len(self.frames) > index:
            f = self.frames.pop()
            self._open_count[f.tag] -= 1
            self._finalize(f)

    def _pop_closing_cells(self, index: int) -> None:
        """終了タグ・「セルを閉じる」で閉じる。仕様は、セル（td・th）とキャプションを閉じるときだけ、書式要素の再開リストを
        最後の境目まで巻き戻す。object・template などの境目は、祖先の終了タグで暗黙に閉じられても巻き戻さない
        （境目の後ろの項目が消えると、続く文字の再開が起きず、隠れた書式要素の中の文字が可視へ漏れる）。"""
        cells = sum(1 for f in self.frames[index:] if f.marker and f.tag in ("td", "th", "caption"))
        self._pop_frames(index)
        for _ in range(cells):
            self._afe_clear_to_marker()

    def _finalize(self, f: _Frame) -> None:
        if f.is_script:
            self._finish_script(f)
        if f.is_anchor:
            self._finish_anchor()
        if f.is_pre:
            self._pre -= 1
        if f.is_foreign:
            self._foreign -= 1
            self._text_ok = f.saved_text_ok
            if self._roots:
                self._roots.pop()
        if f.text_ok:
            self._text_ok -= 1
        if f.afe is not None:
            f.afe.frame = None  # スタックからは外れるが、再開リストには残る（終了タグが来るまで）
        if f.tag in _BLOCK:
            self._brk()

    def _finish_anchor(self) -> None:
        if self._anchor_href is not None:
            text = clean_inline("".join(self._anchor_text))
            self.out.links.append((self._anchor_href, text))
        self._anchor_href = None
        self._anchor_text = []

    def _finish_script(self, f: _Frame) -> None:
        text = "".join(self._script_buf or [])
        self._script_buf = None
        if not text.strip():
            return
        if _JSON_SCRIPT.search(f.script_type) or f.attrs_id == "__NEXT_DATA__":
            self.out.json_scripts.append(text)
            text = _json_strings_joined(text) or text
        self.out.add_hidden(HiddenKind.OTHER, text)

    def finish(self) -> None:
        self.close()
        self._pop_frames(0)
        self._finish_anchor()
        self.out.brk()


def _json_walk_strings(obj: object) -> Iterable[str]:
    """JSON を深さ優先で辿り、文字列の値を出現順に返す（再帰しない＝深い入れ子で落ちない）。"""
    stack: list[object] = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, dict):
            stack.extend(reversed(list(cur.values())))
        elif isinstance(cur, list):
            stack.extend(reversed(cur))


def _json_strings_joined(text: str) -> str:
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return ""
    return "\n".join(_json_walk_strings(obj))


def _parse_html(out: _Collector, html: str, visible_kinds: frozenset[HiddenKind], ctx: _Ctx = _Ctx()) -> None:
    p = _HtmlParser(out, visible_kinds, ctx)
    p.feed(html)
    p.finish()


# --- 本文の取り出し（種別ごと） ------------------------------------------------------------------------
_CHARSET_HEADER = re.compile(r"charset\s*=\s*[\"']?([\w.:\-]+)", re.I)
_CHARSET_META = re.compile(rb"<meta[^>]{0,200}?charset\s*=\s*[\"']?([\w.:\-]+)", re.I)


# ブラウザ（WHATWG）が実際に解釈する文字コードだけを許す。utf-7・unicode_escape などは、ブラウザが無視する宣言で
# 「人が見る本文」と「こちらが読む本文」を食い違わせる経路になるので、宣言があっても UTF-8 として読む。
_SAFE_CODECS = re.compile(
    r"(?:utf_8|utf_8_sig|utf_16|utf_16_le|utf_16_be|ascii|latin_1|iso8859_\d+|cp125\d|cp874|cp932|cp949|cp950|shift_jis|euc_jp|iso2022_jp|"
    r"euc_kr|gbk|gb2312|gb18030|big5|big5hkscs|koi8_[ru])"
)


# WHATWG の「replacement」エンコーディング。ブラウザはこれらを宣言した文書の本文を U+FFFD 1文字にする（何も見えない）。
# UTF-8 として読むと、人には空白の文書の中身がこちらにだけ見えてしまう。
_REPLACEMENT_LABELS = frozenset({"replacement", "hz-gb-2312", "iso-2022-cn", "iso-2022-cn-ext", "iso-2022-kr"})
_META_PRESCAN_BYTES = 1024  # ブラウザが meta の charset を探す先頭のバイト数
_COMMENT_BYTES = re.compile(rb"<!--.*?(?:-->|\Z)", re.S)


def _guess_utf16(body: bytes) -> str | None:
    """宣言も BOM も無い UTF-16 の文書（XML の自動判定と同じ「<」の位置）。UTF-8 の文書に NUL が並ぶことは無い。"""
    head = body[:64]
    if len(head) < 4:
        return None
    even = sum(1 for b in head[0::2] if b == 0)
    odd = sum(1 for b in head[1::2] if b == 0)
    half = len(head) // 2
    if odd >= half * 0.6 and even == 0:
        return "utf_16_le"
    if even >= half * 0.6 and odd == 0:
        return "utf_16_be"
    return None


def _codec_for(label: str) -> str | None:
    """宣言された文字コードのラベルを、読んでよい Python のコーデック名へ（ブラウザの規則に合わせる）。読めなければ None。

    Python の正式名はハイフン入り（utf-16-le・iso8859-1）なので、アンダースコアに揃えて照合する。照合し損ねて
    UTF-8 へ落とすと、UTF-16 の文書（NUL が混ざる）のタグが解析されず、隠し要素の中身が可視へ漏れる。
    """
    try:
        key = codecs.lookup(label).name.replace("-", "_")
    except LookupError:
        return None
    if key == "utf_16":
        return "utf_16_le"  # WHATWG: ラベル "utf-16" は UTF-16LE
    if key in ("ascii", "latin_1", "iso8859_1"):
        return "cp1252"  # WHATWG: これらは windows-1252
    return key if _SAFE_CODECS.fullmatch(key) else None


def decode_body(body: bytes, content_type: str = "") -> str:
    """バイト列を文字列へ。BOM → Content-Type の charset → meta の charset → UTF-8 の順（ブラウザの規則に合わせる）。壊れた列は置換文字。

    meta は先頭 1024 バイトのコメント外だけを見る。meta で宣言した UTF-16 は UTF-8 として扱う（ブラウザの規則）。
    """
    if body.startswith(b"\xef\xbb\xbf"):
        return body[3:].decode("utf-8", "replace")
    if body.startswith((b"\xff\xfe", b"\xfe\xff")):
        return body.decode("utf-16", "replace")
    enc = None
    from_meta = False
    m = _CHARSET_HEADER.search(content_type or "")
    if m:
        enc = m.group(1)
    else:
        mm = _CHARSET_META.search(_COMMENT_BYTES.sub(b"", body[:_META_PRESCAN_BYTES]))
        if mm:
            enc = mm.group(1).decode("ascii", "ignore")
            from_meta = True
    if enc:
        if enc.strip().lower() in _REPLACEMENT_LABELS:
            return "\ufffd"
        name = _codec_for(enc)
        if from_meta and name and name.startswith("utf_16"):
            name = "utf_8"
        if name:
            return body.decode(name, "replace")
    elif not m:
        guess = _guess_utf16(body)
        if guess:
            return body.decode(guess, "replace")
    return body.decode("utf-8", "replace")


_LINE_STARTER = re.compile(r"^\s{0,3}(?:#{1,6}\s|[-*+]\s|\d{1,3}[.)]\s|>|\|)")


def _hide_html_comments(out: _Collector, text: str) -> str:
    """Markdown の HTML コメント（<!-- … -->）を隠しチャネルへ移し、コメントを除いた本文を返す（線形時間）。
    閉じないコメントは末尾まで隠す（ブラウザ・Markdown 描画系の挙動に合わせ、迷ったら隠す側）。"""
    if "<!--" not in text:
        return text
    parts: list[str] = []
    i = 0
    while True:
        j = text.find("<!--", i)
        if j < 0:
            parts.append(text[i:])
            break
        parts.append(text[i:j])
        k = text.find("-->", j + 4)
        if k < 0:
            out.add_hidden(HiddenKind.OTHER, text[j + 4 :])
            break
        out.add_hidden(HiddenKind.OTHER, text[j + 4 : k])
        i = k + 3
    return "".join(parts)


def _plain_blocks(out: _Collector, text: str, *, markdown: bool) -> None:
    """プレーンテキスト／Markdown。空行・見出し・箇条書き・表の行・引用でブロックを分ける。

    Markdown の HTML コメントは隠しチャネルへ（可視に混ぜない）。
    """
    text = text.replace(BLOCK_SEP, " ")
    if markdown:
        text = _hide_html_comments(out, text)
    for line in text.splitlines():
        if not line.strip():
            out.brk()
            continue
        if _LINE_STARTER.match(line):
            out.brk()
        out.add_visible(line + " ")
    out.brk()


def _json_doc_blocks(out: _Collector, text: str, visible_kinds: frozenset[HiddenKind]) -> bool:
    """文書そのものが JSON の場合。文字列の値を1つずつブロックにする（HTML らしい文字列はタグを外して取り出す）。"""
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        return False
    for s in _json_walk_strings(obj):
        if _HTML_LIKE.search(s):
            out.brk()
            _parse_html(out, s, visible_kinds)
        else:
            out.add_visible(s)
        out.brk()
    return True


def _tight(s: str) -> str:
    return _WS.sub("", unicodedata.normalize("NFKC", s.replace(BLOCK_SEP, ""))).casefold()


def _append_unseen_json_html(out: _Collector, visible_tight: str, visible_kinds: frozenset[HiddenKind], ctx: _Ctx = _Ctx()) -> None:
    """__NEXT_DATA__ 等の JSON 内にある HTML 文字列のうち、可視テキストに現れないブロックだけを可視テキストへ追記する。"""
    seen_blocks: set[str] = set()
    total = 0
    for raw in list(out.json_scripts):
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):
            continue
        for s in _json_walk_strings(obj):
            if len(s) < 30 or not _HTML_LIKE.search(s):
                continue
            sub = _Collector()
            _parse_html(sub, s, visible_kinds, ctx)
            for kind, texts in sub.hidden.items():
                for t in texts:
                    out.add_hidden(kind, t)
            for block in sub.blocks:
                t = _tight(block)
                if len(t) < 6 or t in visible_tight or t in seen_blocks:
                    continue
                if total + len(block) > MAX_EMBEDDED_APPEND_CHARS:
                    return
                seen_blocks.add(t)
                total += len(block)
                out.blocks.append(block)


# --- page_class ----------------------------------------------------------------------------------------
def classify_page(
    *,
    status: int | None,
    visible_len: int,
    has_password_input: bool,
    script_count: int,
    has_mount_point: bool = False,
    has_noscript: bool = False,
    is_html: bool = True,
    final_url: str | None = None,
    unfollowed_location: str | None = None,
) -> PageClass:
    """page_class をコードで決める（設計 §3 AUTORUN の裏取りの本体）。

    login_wall / error_page / empty / spa_shell は「検査を減らす」方向なので、強い証拠があるときだけ付ける。
    迷う場合は CONTENT（検査を続ける側）に倒す。
    """
    st = status or 200
    if st in (401, 403):
        return PageClass.LOGIN_WALL
    if st >= 400:
        return PageClass.ERROR_PAGE
    if 300 <= st < 400:  # 追跡しなかった転送（スコープ外・非グローバルへの転送）。認証壁の証拠になる
        if unfollowed_location and href_looks_like_login(unfollowed_location):
            return PageClass.LOGIN_WALL
        return PageClass.EMPTY
    if has_password_input and visible_len < LOGIN_WALL_MAX_VISIBLE:
        return PageClass.LOGIN_WALL
    if final_url and visible_len < LOGIN_WALL_MAX_VISIBLE and href_looks_like_login(final_url):
        return PageClass.LOGIN_WALL
    if is_html and visible_len < SPA_SHELL_MAX_VISIBLE and script_count >= 1 and (has_mount_point or has_noscript or script_count >= 2):
        return PageClass.SPA_SHELL
    if visible_len == 0:
        return PageClass.EMPTY
    return PageClass.CONTENT


def _visible_len(text: str) -> int:
    return sum(1 for ch in text if not ch.isspace() and ch != BLOCK_SEP)


# --- 入口 ----------------------------------------------------------------------------------------------
_C0_AND_SPACE = "".join(chr(i) for i in range(0x21))
_URL_STRIP_CHARS = re.compile("[\t\n\r]")
_LEADING_SLASHES = re.compile(r"^((?:https?:)?)/{3,}", re.I)


def _resolve_href(base: str, href: str) -> str:
    """href をブラウザと同じ規則（WHATWG の http/https の部分）で絶対URLにする。

    先頭末尾の制御文字・空白を除き、途中のタブ・改行を除く。http/https では、パス部分（? か # の前）のバックスラッシュを
    スラッシュとして読む（"\\\\other.example\\x" はブラウザでは別のサイトへ行くが、urljoin は同じサイトの相対パスにする）。
    """
    href = _URL_STRIP_CHARS.sub("", href.strip(_C0_AND_SPACE))
    if base[:5].lower() in ("http:", "https"):
        if "\\" in href:
            cut = min((i for i in (href.find("?"), href.find("#")) if i >= 0), default=len(href))
            href = href[:cut].replace("\\", "/") + href[cut:]
        href = _LEADING_SLASHES.sub(r"\1//", href)  # "///host/p" や "https:///host/p" は、ブラウザでは「//host/p」と同じ（余分な / を読み飛ばす）
    return urljoin(base, href)


def _url_char_ok(c: str) -> bool:
    o = ord(c)
    if 0x21 <= o < 0x7F:
        return True
    return o >= 0x80 and not (is_unsafe_char(c) or c.isspace() or o in _FILLER_TABLE or _is_variation_selector_char(c))


def _is_variation_selector_char(c: str) -> bool:
    return "\ufe00" <= c <= "\ufe0f" or "\U000e0100" <= c <= "\U000e01ef"


def _safe_url_text(url: str) -> str:
    """URL の文字列に残った制御文字・ゼロ幅・bidi・不可視の塗りつぶし・空白を %XX にする（ブラウザが送る形。
    表示・ログへ出る文字列を安全にする）。"""
    if all(_url_char_ok(c) for c in url):
        return url
    return "".join(c if _url_char_ok(c) else quote(c.encode("utf-8")) for c in url)


def _resolve_links(
    raw: list[tuple[str, str]], base: str, scope: Sequence[UrlPrefix], *, docs_role: bool = False
) -> tuple[LinkEntry, ...]:
    entries: list[LinkEntry] = []
    seen: set[str] = set()
    own = urlsplit(base)._replace(fragment="").geturl() if base else ""
    for href, anchor in raw:
        if len(entries) >= MAX_LINKS:
            break
        if href.startswith("#"):
            continue  # ページ内リンク
        try:
            abs_url = _resolve_href(base, href)
            parts = urlsplit(abs_url)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        abs_url = _safe_url_text(parts._replace(fragment="").geturl())
        if len(abs_url) > 2048 or abs_url in seen or abs_url == own:
            continue  # 重複・自分自身へのリンク（取得済み）は載せない
        seen.add(abs_url)
        role = LinkRole.LOGIN if href_looks_like_login(abs_url) else LinkRole.DOCS if docs_role and href_looks_like_docs(abs_url) else LinkRole.OTHER
        entries.append(
            LinkEntry(
                link_id=f"L{len(entries) + 1}",
                href=abs_url,
                anchor_text=escape_for_display(anchor, ANCHOR_MAX_CHARS) if anchor else "",
                role=role,
                in_scope=link_in_scope(abs_url, scope),
            )
        )
    return tuple(entries)


@dataclass(frozen=True)
class _Hidden:
    kind: HiddenKind
    text: str


def _hidden_channels(out: _Collector) -> list[_Hidden]:
    res = []
    for kind in _KIND_ORDER:
        texts = out.hidden.get(kind)
        if texts:
            res.append(_Hidden(kind, "\n".join(texts)))
    return res


def sanitize(
    result: FetchResult,
    *,
    doc_id: str,
    role: DocRole,
    label: str,
    scope: Sequence[UrlPrefix] = (),
    visible_hidden_kinds: Iterable[HiddenKind] = (),
    neutralize_injections: bool = False,
    embedded_json: JsonPolicy = "hidden",
    style_rules: bool | None = None,
) -> SanitizedDoc:
    """取得結果（outcome=ok）を SanitizedDoc へ。想定外の入力は例外にせず、落とせるものは落として返す。

    scope: リンクの in_scope の判定に使う取得スコープ（プリセットの allowed_prefixes）。
    visible_hidden_kinds: 可視扱いにする「構造的な隠し」の種別（spec の hidden 属性・タブ等。既定は空＝全部隠す）。
    neutralize_injections: True なら、可視の注入区間を〔注入疑い〕へ置換する（既定は書き換えない）。
    embedded_json: "append_unseen" は role=spec の時だけ有効（submission は隠しチャネルを厳格に分離）。
    style_rules: 同じ文書の <style> にあるクラス・id・タグの単純な規則で隠れる要素も隠す。None（既定）は submission だけ。
    """
    if result.outcome is not FetchOutcome.OK:
        raise ValueError("sanitize は outcome=ok の取得結果だけを受け取ります")
    kind = result.content_kind
    if kind is ContentKind.UNSUPPORTED:
        raise ValueError("許可リスト外の Content-Type は sanitize できません")
    visible_kinds = frozenset(visible_hidden_kinds)

    content_type = result.headers.get("content-type", "")
    text = decode_body(result.body, content_type)
    if kind is None:
        kind = ContentKind.HTML if ("html" in content_type.lower() or text.lstrip()[:1] == "<") else ContentKind.PLAIN
    is_html = kind in (ContentKind.HTML, ContentKind.XHTML)

    out = _Collector()
    ctx = _Ctx()
    if is_html:
        # 同じ文書の <style> のクラス規則は submission だけで評価する（spec は要件の置き場で、レイアウト用の
        # display:none（タブ・レスポンシブ）が本物の要件文を消すと取りこぼしになる。要項は主催者の文書で敵対的でもない）。
        use_rules = (role is DocRole.SUBMISSION) if style_rules is None else style_rules
        ctx = _probe(text, visible_kinds, want_styles=use_rules)
        _parse_html(out, text, visible_kinds, ctx)
    elif kind is ContentKind.JSON:
        if not _json_doc_blocks(out, text, visible_kinds):
            _plain_blocks(out, text, markdown=False)
    else:
        _plain_blocks(out, text, markdown=kind is ContentKind.MARKDOWN)

    if is_html and embedded_json == "append_unseen" and role is DocRole.SPEC and out.json_scripts:
        _append_unseen_json_html(out, _tight(BLOCK_SEP.join(out.blocks)), visible_kinds, ctx)

    visible_text = strip_unsafe(BLOCK_SEP.join(out.blocks))
    visible_len = _visible_len(visible_text)

    base_url = result.final_url or result.requested_url
    if out.base_href:
        try:
            joined = _resolve_href(base_url, out.base_href)
            if urlsplit(joined).scheme in ("http", "https"):
                base_url = joined
        except ValueError:
            pass
    links = _resolve_links(out.links, base_url, scope, docs_role=role is DocRole.SUBMISSION) if is_html else ()

    last_hop = result.redirects[-1] if result.redirects else None
    unfollowed = last_hop.location if (last_hop is not None and not last_hop.followed) else None
    page_class = classify_page(
        status=result.status,
        visible_len=visible_len,
        has_password_input=out.has_password,
        script_count=out.script_count,
        has_mount_point=out.has_mount,
        has_noscript=out.has_noscript,
        is_html=is_html,
        final_url=result.final_url or result.requested_url,
        unfollowed_location=unfollowed,
    )

    hidden = _hidden_channels(out)
    channels = tuple(
        HiddenChannel(kind=h.kind, length=len(h.text), sha256=hashlib.sha256(h.text.encode("utf-8", "replace")).hexdigest())
        for h in hidden
    )

    # 注入の検知（可視は visible_text 上の区間、隠しは channel の添字）
    vis_matches = inject_scan.limit_matches(inject_scan.scan(visible_text), VISIBLE_SIGNAL_CAP)
    snippets = [escape_for_display(visible_text[m.start : m.end], SNIPPET_CHARS) for m in vis_matches]
    if neutralize_injections and vis_matches:
        visible_text, spans = inject_scan.neutralize(visible_text, vis_matches)
        regions = spans  # 置換後の文字列上のプレースホルダ区間
    else:
        regions = [(m.start, m.end) for m in vis_matches]  # 書き換えない場合は、一致区間そのもの
    signals: list[InjectionSignal] = [
        InjectionSignal(pattern_id=m.pattern_id, doc_id=doc_id, visible=True, start=s, end=e, snippet=sn)
        for m, (s, e), sn in zip(vis_matches, regions, snippets)
    ]
    for idx, h in enumerate(hidden):
        for m in inject_scan.scan(h.text):
            if len(signals) >= MAX_SIGNALS_PER_DOC:
                break
            signals.append(
                InjectionSignal(
                    pattern_id=m.pattern_id,
                    doc_id=doc_id,
                    visible=False,
                    channel=idx,
                    snippet=escape_for_display(h.text[m.start : m.end], SNIPPET_CHARS),
                )
            )

    return SanitizedDoc(
        doc_id=doc_id,
        role=role,
        label=label,
        url=result.final_url or result.requested_url,
        sha256=result.body_sha256,
        byte_length=len(result.body),
        truncated=result.truncated,
        page_class=page_class,
        signals=PageSignals(http_status=result.status, has_password_input=out.has_password, script_count=out.script_count),
        visible_text=visible_text,
        links=links,
        hidden=channels,
        injection_signals=tuple(signals),
    )
