"""http_probe が本文先頭 64KB から取り出すコード算出の指標（設計 §4 http_probe・§3 AUTORUN の裏取り）。

標準ライブラリの html.parser だけで、次を数える（本文のテキストは返さない。数値・真偽だけ）:
  * password 欄（<input type=password>。hidden 属性・display:none・type=hidden・template/noscript/textarea の中は数えない）
  * ログインフォームの形（password 欄を含む form、または action がログイン用パスの form）
  * 可視テキストの長さ（script/style/noscript/template/head を除く）・script の数・SPA の描画先の印
  * <meta http-equiv=refresh> の転送先パス（静的ホスティングのログイン転送）

限界（設計 §5-2 と同じ）: インライン style と属性だけを見る。外部 CSS・親要素の hidden・JS 描画は評価できない
（JS で描く画面は spa_shell と判定して確認不能にする）。入力は先頭 64KB に切ってから走らせる。

敵対レビューで足した防御（提出物の側が「パーサには見えない password 欄」を作って壁を隠す回避への備え）:
  * 同じ属性が重複したら先頭を採る（HTML の規則。type="password" type="text" はブラウザでは password 欄）。
  * 文字コードは BOM を先に見る（UTF-8/UTF-16）。charset=utf-16 系の宣言も読む（読めないと本文が文字化けして何も見えない）。
  * 生の文字列にも「type=password の入力欄らしい記述」があるのに、パーサが入力欄と数えなかった時は password_unconfirmed を立てる
    （壊れたコメント・CDATA・<textarea/>・<textarea><script> などのパーサとブラウザの解釈の食い違い）。強い証拠にはせず、
    「開ける」とも言わない。囲まれている文脈（script の文字列・コメント・template）は問わない＝見落とすより不確定にする側。
    ログインの画面を JS の文字列で組み立てるページも不確定になる（許容する損失）。
  * <meta refresh> の行き先は、パスだけでなく URL をそのまま残す（外部 IdP への転送を行き先のホストで判定するため）。
"""
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.contracts import PROBE_BODY_MAX_BYTES
from app.ingest.sanitize import decode_body as ingest_decode_body

# SPA の描画先としてよく使われる id（本文がほぼ空で script がある時の裏取りに使う）
_MOUNT_IDS = frozenset({"root", "app", "__next", "__nuxt", "___gatsby", "app-root", "svelte", "q-app"})
# 中身を「見えるテキスト／入力欄」として扱わない要素（実行時の画面に出ない）
_SKIP_TAGS = frozenset({"template", "noscript", "textarea", "script", "style"})
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)
_JS_WORDS = re.compile(r"javascript|enable\s+js|有効", re.IGNORECASE)
_LOGIN_TITLE = re.compile(r"ログイン|サインイン|log\s*-?in|sign\s*-?in|認証", re.IGNORECASE)
_META_REFRESH = re.compile(r"^\s*(\d+)\s*[;,]\s*(?:url\s*=\s*)?['\"]?([^'\"\s]+)", re.IGNORECASE)
# ログインを促す語（題名・短い本文）。「認証」は含めない（認証の解説ページを壁と取り違えない）
_LOGIN_PROMPT = re.compile(r"ログイン|サインイン|log\s*-?\s*in|sign\s*-?\s*in", re.IGNORECASE)
# 「ログイン不要」「without logging in」など、ログインを求めていない言い回し（これを語として数えない）
_LOGIN_NEGATED = re.compile(
    r"(?:ログイン|サインイン|log\s*-?\s*in|sign\s*-?\s*in)\s*(?:は|も|を)?\s*(?:不要|なし|無し|いりません|必要ありません|必要なし|しなくて|せずに|せず)|"
    r"(?:no|without|never\s+need\s+to|don'?t\s+need\s+to)\s+(?:log\s*-?\s*in|sign\s*-?\s*in|logging\s+in|signing\s+in)",
    re.IGNORECASE,
)
# 拒否・エラーの文言（HTTP 200 で返る「ソフト404」「ソフト403」。短い画面の題名・本文にあれば、中身のあるページではない）
_ERROR_WORDS = re.compile(
    r"access\s+denied|forbidden|unauthori[sz]ed|not\s+authori[sz]ed|permission\s+denied|not\s+found|page\s+(?:does\s+not|doesn'?t)\s+exist|"
    r"(?<![\d,.])40[134](?![\d,.])|アクセス(?:が|は)?(?:拒否|できません|制限)|権限(?:が|は)(?:ありません|必要)|閲覧(?:権限|できません)|"
    r"ページ(?:が|は)(?:見つかりません|存在しません)|お探しのページ|認証(?:が)?必要",
    re.IGNORECASE,
)
LOGIN_PROMPT_TITLE_TEXT_MAX = 300  # 題名にログインの語があり、本文がこの字数以下ならログインを促す画面とみなす
LOGIN_PROMPT_TEXT_ONLY_MAX = 120  # 題名に無くても、本文全体がこの字数以下でログインの語があれば同じ
# 生の文字列から見た「password 欄らしい記述」。属性名の途中（data-type=）には当たらない。長さに上限を置き、悪意ある入力でも線形時間
_PASSWORD_HINT = re.compile(r"<\s*input\b[^>]{0,1000}?(?<![\w-])type\s*=\s*[\"']?\s*password\b", re.IGNORECASE)
_CUSTOM_ELEMENT = re.compile(r"[a-z][a-z0-9]*-[a-z0-9._-]*")
_RESERVED_HYPHEN_TAGS = frozenset(
    {"annotation-xml", "color-profile", "font-face", "font-face-src", "font-face-uri", "font-face-format", "font-face-name", "missing-glyph"}
)


@dataclass(frozen=True)
class FormInfo:
    """form 1つの要約（action のパスだけ。ホスト・クエリは持たない）。"""

    action_path: str
    has_password: bool
    other_inputs: int  # password 以外の見える入力欄（text/email/tel/number など）


@dataclass(frozen=True)
class HtmlSignals:
    has_password_input: bool
    forms: tuple[FormInfo, ...]
    text_len: int  # 可視テキスト（空白を1つにまとめた後）の字数
    script_count: int
    mount_marker: bool  # 描画先 id、または noscript に「JavaScript が必要」系の文
    title_login_words: bool  # <title> がログイン系の語を含む
    meta_refresh_path: str | None  # <meta http-equiv=refresh> の転送先のパス（ホストは捨てる）
    # 以下は敵対レビューで足した指標（既定値つき＝従来の組み立てを壊さない）
    embed_count: int = 0  # <iframe>・<frame>・<embed>・<object> の数（中身が別の場所にある）
    meta_refresh_target: str | None = None  # <meta refresh> の行き先の URL（行き先のホストで IdP を判定するための材料。facts には載せない）
    meta_refresh_delay: int | None = None  # その待ち秒数
    password_unconfirmed: bool = False  # 生の文字列に password 欄らしい記述があるのに、パーサは入力欄と数えなかった
    login_prompt: bool = False  # 短い画面（題名か本文）がログインを促している
    error_prompt: bool = False  # 短い画面（題名か本文）が拒否・エラーの文言を出している（HTTP 200 のソフト403・ソフト404）


def decode_body(body: bytes, content_type: str | None) -> str:
    """本文を文字列にする。読み方は sanitize（本文を読む側）と同じ1つの実装を使う。

    ログイン画面を探す側と本文を読む側で文字コードの読みが割れると、人が見る画面（ブラウザ）と食い違う。
    実際に、UTF-8 の画面に `<meta charset=utf-16>` を足すだけで password 欄が読めず「誰でも開ける」になった
    （ブラウザは meta で宣言された UTF-16 を UTF-8 として読む）。規則（BOM → ヘッダ → meta 先頭1024バイト・
    コメント外 → BOM 無し UTF-16 の推定、replacement 系の扱い、許可リスト）は sanitize.decode_body が持つ。
    """
    return ingest_decode_body(body, content_type or "")


_NUMERIC_REF = re.compile(r"&#(?:[xX]([0-9a-fA-F]{1,6})|([0-9]{1,7}));?")


def _decode_ascii_refs(text: str) -> str:
    """数字の文字参照のうち、英数字になるものだけ復号する（type=&#112;assword を生の文字列の照合で見落とさない）。

    < > & " ' になる参照は復号しない（文章として書かれたコード例が入力欄の記述に化けないように）。
    """

    def repl(m: re.Match[str]) -> str:
        cp = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        ch = chr(cp) if cp < 0x80 else ""
        return ch if ch.isalnum() else m.group(0)

    return _NUMERIC_REF.sub(repl, text)


def _path_of(url: str) -> str:
    try:
        return urlsplit(url.strip()).path or "/"
    except ValueError:
        return ""


class _Scanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip: dict[str, int] = {}
        self._in_head = False
        self._in_title = False
        self._form: dict[str, object] | None = None
        self.forms: list[FormInfo] = []
        self.password = 0
        self.script_count = 0
        self.mount = False
        self.noscript_js = False
        self.embeds = 0
        self.title: list[str] = []
        self.text: list[str] = []
        self.meta_refresh_path: str | None = None
        self.meta_refresh_target: str | None = None
        self.meta_refresh_delay: int | None = None

    # 見えない領域（template / noscript / textarea / script / style）の中か
    def _skipping(self) -> bool:
        return any(n > 0 for n in self._skip.values())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a: dict[str, str] = {}
        for k, v in attrs:
            a.setdefault(k.lower(), v if v is not None else "")  # 重複した属性は先頭が有効（HTML の規則）
        in_skip = self._skipping()
        if tag == "head":
            self._in_head = True
        elif tag == "title":
            self._in_title = True
        elif tag == "script":
            if not in_skip:
                self.script_count += 1
        if tag in _SKIP_TAGS:
            self._skip[tag] = self._skip.get(tag, 0) + 1
            return
        if in_skip:
            return
        if a.get("id", "").lower() in _MOUNT_IDS or (_CUSTOM_ELEMENT.fullmatch(tag) and tag not in _RESERVED_HYPHEN_TAGS):
            self.mount = True  # 描画先の id、またはカスタム要素（Angular の app-root など。描画先の印）
        if tag in ("iframe", "frame", "embed", "object"):
            self.embeds += 1
        if tag == "meta" and a.get("http-equiv", "").lower().strip() == "refresh":
            m = _META_REFRESH.match(a.get("content", ""))
            if m and self.meta_refresh_path is None:
                self.meta_refresh_delay = int(m.group(1)[:6])
                self.meta_refresh_target = m.group(2)[:2048]
                self.meta_refresh_path = _path_of(m.group(2))
        elif tag == "form":
            self._form = {"action": _path_of(a.get("action", "")), "password": False, "others": 0}
        elif tag == "input":
            self._on_input(a)

    def _on_input(self, a: dict[str, str]) -> None:
        itype = a.get("type", "text").strip().lower() or "text"
        if itype in ("hidden", "submit", "button", "reset", "image", "checkbox", "radio", "file", "search"):
            return  # 見える認証欄ではない（search は検索フォーム。password と取り違えない）
        if "hidden" in a or a.get("aria-hidden", "").lower() == "true" or _HIDDEN_STYLE.search(a.get("style", "")):
            return
        if itype == "password":
            self.password += 1
            if self._form is not None:
                self._form["password"] = True
        elif self._form is not None:
            self._form["others"] = int(self._form["others"]) + 1  # type: ignore[call-overload]

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # <input ... /> のような自己終了形。開始・終了が対にならない形（<title/> など）で状態が残らないよう、
        # 状態を持たない input / meta だけを処理する。
        if tag in ("input", "meta"):
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            if self._skip.get(tag, 0) > 0:
                self._skip[tag] -= 1
            return
        if tag == "head":
            self._in_head = False
        elif tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            self.forms.append(
                FormInfo(
                    action_path=str(self._form["action"]),
                    has_password=bool(self._form["password"]),
                    other_inputs=int(self._form["others"]),  # type: ignore[call-overload]
                )
            )
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title.append(data)
            return
        if self._skip.get("noscript", 0) > 0 and self._skip.get("template", 0) == 0:
            if _JS_WORDS.search(data):
                self.noscript_js = True
            return
        if self._skipping() or self._in_head:
            return
        self.text.append(data)


def _asks_to_log_in(text: str) -> bool:
    """文章がログインを促しているか。NFKC に畳み（全角英字で語をすり抜けさせない）、「ログイン不要」などの否定は数えない。"""
    t = _LOGIN_NEGATED.sub(" ", unicodedata.normalize("NFKC", text))
    return _LOGIN_PROMPT.search(t) is not None


def _shows_error(text: str) -> bool:
    return _ERROR_WORDS.search(unicodedata.normalize("NFKC", text)) is not None


def analyze_html(body: bytes, content_type: str | None = None) -> HtmlSignals:
    """本文（先頭 64KB まで）から指標を作る。壊れた HTML でも例外を出さない。"""
    sc = _Scanner()
    text_raw = decode_body(body[:PROBE_BODY_MAX_BYTES], content_type)
    try:
        sc.feed(text_raw)
        sc.close()
    except Exception:  # noqa: BLE001  パーサの想定外の入力で落ちない（得られた分だけで判定する）
        pass
    if sc._form is not None:  # 閉じられなかった form も数える
        sc.forms.append(
            FormInfo(str(sc._form["action"]), bool(sc._form["password"]), int(sc._form["others"]))  # type: ignore[call-overload]
        )
    visible = " ".join("".join(sc.text).split())
    title = " ".join("".join(sc.title).split())
    has_password = sc.password > 0
    # 生の文字列の全体を見る（script・style・コメント・textarea の中も）。<textarea><script></textarea> のように、パーサの文脈の解釈が
    # ブラウザと食い違うと、入力欄が「script の中」に見えてしまうため、囲まれている文脈で除外しない。
    hint = bool(_PASSWORD_HINT.search(_decode_ascii_refs(text_raw)))
    prompt_in_title = _asks_to_log_in(title) and len(visible) <= LOGIN_PROMPT_TITLE_TEXT_MAX
    prompt_in_text = len(visible) <= LOGIN_PROMPT_TEXT_ONLY_MAX and _asks_to_log_in(visible)
    error_in_title = _shows_error(title) and len(visible) <= LOGIN_PROMPT_TITLE_TEXT_MAX
    error_in_text = len(visible) <= LOGIN_PROMPT_TEXT_ONLY_MAX and _shows_error(visible)
    return HtmlSignals(
        has_password_input=has_password,
        forms=tuple(sc.forms),
        text_len=len(visible),
        script_count=sc.script_count,
        mount_marker=sc.mount or sc.noscript_js,
        embed_count=sc.embeds,
        title_login_words=bool(_LOGIN_TITLE.search(title)),
        meta_refresh_path=sc.meta_refresh_path,
        meta_refresh_target=sc.meta_refresh_target,
        meta_refresh_delay=sc.meta_refresh_delay,
        password_unconfirmed=hint and not has_password,
        login_prompt=prompt_in_title or prompt_in_text,
        error_prompt=error_in_title or error_in_text,
    )
