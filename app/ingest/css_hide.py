"""CSS（インライン style と、同じ文書の <style> の単純なルール）から「人の目に見えなくなる」指定を拾う。sanitize の部品。

方針（迷ったら「隠す側」へ倒す。隠し損ないは注入文を可視側へ漏らすが、隠し過ぎは表示が減るだけ）:
  * 宣言は「最後が勝つ」で解かない。同じプロパティの宣言のどれか1つでも隠す値なら隠す。ブラウザは壊れた宣言を捨て、
    `!important` を優先するので、「display:none;display:xyz」「display:none !important;display:block」のように
    後ろへ別の値を足して隠しを外したように見せる細工が、最後勝ちの実装ではすり抜ける。
  * 評価できないもの（外部 CSS・var()・複雑なセレクタ・条件付きのメディアクエリ内のルール。@media all や screen など、どの画面でも
    真になるものは評価する）は評価しない。これは限界で、構造（Reader はツールを持たない・出力は検証される）が主防御である。
  * 速度: 入力は敵対的に作られる（1MiB の style 属性など）。正規表現の `.*?` を閉じない記号に何度も当てる書き方
    （二乗時間）を避け、find ベースの線形走査にする。
"""
import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.contracts import HiddenKind

# --- 小さな部品 ----------------------------------------------------------------------------------------
_CSS_ESCAPE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f]?|(.))", re.S)
# 数。\d+ と \d* が重ならない書き方にする（"\d+\.?\d*" は、数字が長く続いて後ろが合わないとき二乗時間で戻り続ける）
_NUM = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?"
_DIM = re.compile(rf"({_NUM})([a-z%]*)")
_IMPORTANT = re.compile(r"\s*!\s*important\s*$")

# 近似の換算（px）。font-size の「読めない小ささ」の判定にだけ使う。
_FONT_PX = {
    "px": 1.0, "pt": 4 / 3, "pc": 16.0, "in": 96.0, "cm": 96 / 2.54, "mm": 96 / 25.4, "q": 96 / 101.6,
    "em": 16.0, "rem": 16.0, "ex": 8.0, "ch": 8.0, "%": 0.16, "vw": 8.0, "vh": 8.0, "vmin": 8.0, "vmax": 8.0,
}  # fmt: skip
_ABS_PX = frozenset({"", "px", "pt", "pc", "cm", "mm", "in", "q"})  # 絶対長（位置のずれの大きさをそのまま比べられる）

FONT_MIN_READABLE_PX = 2.0  # これ未満の文字は人に読めない
ALPHA_INVISIBLE = 0.05  # opacity・文字色の不透明度がこれ以下なら、人にはほぼ見えない
OFFSET_FAR_NEGATIVE_PX = -1000.0
OFFSET_FAR_POSITIVE_PX = 5000.0


def strip_css_comments(s: str) -> str:
    """CSS コメントを空白1つに置き換える（線形時間）。閉じないコメントは末尾まで消える（CSS の仕様どおり）。"""
    if "/*" not in s:
        return s
    out: list[str] = []
    i = 0
    while True:
        j = s.find("/*", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        k = s.find("*/", j + 2)
        if k < 0:
            break
        out.append(" ")
        i = k + 2
    return "".join(out)


def css_unescape(s: str) -> str:
    def rep(m: "re.Match[str]") -> str:
        if m.group(1):
            cp = int(m.group(1), 16)
            return chr(cp) if 0 < cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF else "�"
        return m.group(2)

    return _CSS_ESCAPE.sub(rep, s) if "\\" in s else s


def _unwrap(v: str) -> str:
    """calc(...) と余分な括弧を外す（calc(0px)・calc((0)) の類）。入れ子の演算は評価しない。"""
    v = v.strip()
    while True:
        if v.startswith("calc(") and v.endswith(")"):
            start = 4
        elif v.startswith("(") and v.endswith(")"):
            start = 0
        else:
            return v
        depth = 0
        for idx in range(start, len(v)):
            ch = v[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx != len(v) - 1:
                    return v  # 外側の括弧が全体を囲っていない（a(b) + c(d) の類）
        v = v[start + 1 : -1].strip()


def _dim(v: str) -> tuple[float, str] | None:
    m = _DIM.fullmatch(_unwrap(v))
    if not m:
        return None
    try:
        return float(m.group(1)), m.group(2)
    except ValueError:
        return None


def _is_zero(v: str) -> bool:
    d = _dim(v)
    return d is not None and d[0] == 0


def _font_px(v: str) -> float | None:
    d = _dim(v)
    if d is None:
        return None
    n, unit = d
    if n == 0:
        return 0.0
    f = _FONT_PX.get(unit)
    return abs(n) * f if f is not None else None


def _font_shorthand_px(v: str) -> float | None:
    """font ショートハンドの文字サイズ（`font:0/0 serif`・`font:700 0px/1 x`）。"""
    for tok in v.split():
        head = tok.split("/", 1)[0]
        if "/" in tok or head == "0" or re.fullmatch(rf"{_NUM}[a-z%]+", head):
            px = _font_px(head)
            if px is not None:
                return px
    return None


def _alpha_num(a: str) -> float | None:
    a = a.strip()
    if a == "none":
        return 0.0
    try:
        if a.endswith("%"):
            return float(a[:-1]) / 100
        return float(a)
    except ValueError:
        return None


def alpha_of_color(v: str) -> float | None:
    """色の不透明度（0〜1）。読めなければ None。"""
    v = _unwrap(v)
    if v == "transparent":
        return 0.0
    m = re.fullmatch(r"#([0-9a-f]{4}|[0-9a-f]{8})", v)
    if m:
        h = m.group(1)
        return int(h[3] * 2 if len(h) == 4 else h[6:8], 16) / 255
    m = re.fullmatch(r"(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\((.*)\)", v)
    if not m:
        return None
    name, inner = m.groups()
    if "/" in inner:
        return _alpha_num(inner.rsplit("/", 1)[1])
    if name in ("rgba", "hsla"):
        parts = [p.strip() for p in inner.split(",")]
        if len(parts) == 4:
            return _alpha_num(parts[3])
    return None


def _color_key(v: str) -> str:
    v = re.sub(r"\s+", "", v.lower())
    m = re.fullmatch(r"#([0-9a-f])([0-9a-f])([0-9a-f])", v)
    return "#" + "".join(c * 2 for c in m.groups()) if m else v


def _opacity_value(v: str) -> float | None:
    v = _unwrap(v)
    try:
        return float(v[:-1]) / 100 if v.endswith("%") else float(v)
    except ValueError:
        return None


def _far_offset(tok: str, *, positive: bool) -> bool:
    """位置・余白・字下げ・移動量の1つの値が、画面の外へ飛ばす大きさか。"""
    d = _dim(tok)
    if d is None:
        return False
    n, unit = d
    if unit in _ABS_PX:
        return n <= OFFSET_FAR_NEGATIVE_PX or (positive and n >= OFFSET_FAR_POSITIVE_PX)
    if unit == "%":
        return n <= -100 or (positive and n >= 1000)
    return n <= -100 or (positive and n >= 300)  # em/rem/ch/ex/vw/vh


_OFFSET_POSITIONAL = ("left", "right", "top", "bottom", "inset", "inset-inline", "inset-block", "inset-inline-start", "inset-inline-end",
                      "inset-block-start", "inset-block-end", "translate", "text-indent")  # fmt: skip
_OFFSET_MARGIN = ("margin", "margin-left", "margin-right", "margin-top", "margin-bottom", "margin-inline", "margin-block",
                  "margin-inline-start", "margin-inline-end", "margin-block-start", "margin-block-end")  # fmt: skip
# 引数の長さを抑える（「translate(」を並べて閉じない入力で、開始位置ごとに末尾まで読む二乗時間を避ける）
_TRANSLATE_FN = re.compile(r"translate(?:3d|x|y|z)?\(([^)]{0,120})\)")
_SCALE_FN = re.compile(r"scale(?:3d|x|y)?\(([^)]{0,120})\)")
_FILTER_OPACITY = re.compile(r"opacity\(\s*([^)]{0,60})\)")


def parse_declarations(style: str) -> list[tuple[str, str]]:
    """style 属性・ルールの本文から (プロパティ, 値) を出現順にすべて返す。コメント除去・エスケープ復号・小文字化・!important 除去済み。"""
    out: list[tuple[str, str]] = []
    for part in css_unescape(strip_css_comments(style)).split(";"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        out.append((k.strip().lower(), _IMPORTANT.sub("", v.strip().lower())))
    return out


def kinds_from_declarations(decls: Iterable[tuple[str, str]], *, transparent: bool = True) -> set[HiddenKind]:
    """宣言の並びから、人の目に見えなくなる種別を返す。同じプロパティのどれか1つでも隠す値なら隠す。

    transparent=False では、文字色の透明を隠しとして扱わない。クラス単位の規則は、要素の別のクラスの規則（背景の
    グラデーションを足す・背景を文字の形に切り抜くなど）と組み合わさって見える文字を作る（Tailwind の text-transparent
    など）ので、文書に「背景を文字に切り抜く」指定があるときは、1つの規則だけでは見えないと言い切れない。"""
    by: dict[str, list[str]] = {}
    for k, v in decls:
        by.setdefault(k, []).append(v)
    kinds: set[HiddenKind] = set()

    def vals(*names: str) -> list[str]:
        return [v for n in names for v in by.get(n, ())]

    if any(v == "none" for v in vals("display")) or any(v == "hidden" for v in vals("content-visibility")):
        kinds.add(HiddenKind.CSS_DISPLAY_NONE)
    if any(v in ("hidden", "collapse") for v in vals("visibility")):
        kinds.add(HiddenKind.CSS_VISIBILITY_HIDDEN)

    # 不透明度ゼロに近い／文字色が透明／背景と同じ色／filter:opacity(0)
    invisible = False
    for v in vals("opacity"):
        o = _opacity_value(v)
        if o is not None and o <= ALPHA_INVISIBLE:
            invisible = True
    # 文字の形に切り抜いた背景（グラデーション文字）は color:transparent が普通に使われる。背景の絵が無いなら見えない。
    paints_text = any("text" in v for v in vals("background-clip", "-webkit-background-clip")) and any(
        "gradient(" in v or "url(" in v for v in vals("background", "background-image")
    )
    if transparent and not paints_text:
        for v in vals("color", "-webkit-text-fill-color", "text-fill-color"):
            a = alpha_of_color(v)
            if a is not None and a <= ALPHA_INVISIBLE:
                invisible = True
    for v in vals("filter", "-webkit-filter", "backdrop-filter"):
        for arg in _FILTER_OPACITY.findall(v):
            o = _opacity_value(arg)
            if o is not None and o <= ALPHA_INVISIBLE:
                invisible = True
    bg = {_color_key(v) for v in vals("background-color")} | {_color_key(v) for v in vals("background") if " " not in v.strip()}
    if bg and any(_color_key(v) in bg for v in vals("color")):
        invisible = True  # 同じ要素の中で文字色と背景色が同じ（親の背景との同色は評価できない）
    if invisible:
        kinds.add(HiddenKind.CSS_OPACITY_ZERO)

    # 読めない小ささ
    for v in vals("font-size"):
        px = _font_px(v)
        if px is not None and px < FONT_MIN_READABLE_PX:
            kinds.add(HiddenKind.CSS_FONT_SIZE_ZERO)
    for v in vals("font"):
        px = _font_shorthand_px(v)
        if px is not None and px < FONT_MIN_READABLE_PX:
            kinds.add(HiddenKind.CSS_FONT_SIZE_ZERO)

    # 画面外・切り抜き・大きさゼロ
    off = False
    for prop in _OFFSET_POSITIONAL:
        for v in by.get(prop, ()):
            if any(_far_offset(t, positive=True) for t in v.split()):
                off = True
    for prop in _OFFSET_MARGIN:
        for v in by.get(prop, ()):
            if any(_far_offset(t, positive=False) for t in v.split()):
                off = True
    for v in vals("transform", "-webkit-transform"):
        for args in _TRANSLATE_FN.findall(v):
            if any(_far_offset(t, positive=True) for t in re.split(r"[,\s]+", args.strip()) if t):
                off = True
        for args in _SCALE_FN.findall(v):
            parts = [t for t in re.split(r"[,\s]+", args.strip()) if t]
            if any(_is_zero(t) for t in parts[:2]):
                off = True
    for v in vals("scale"):
        if any(_is_zero(t) for t in v.split()[:2]):
            off = True
    for v in vals("clip"):
        nums = re.findall(rf"({_NUM})(px)?", v) if v.startswith("rect(") else []
        if nums and len(nums) >= 4 and all(abs(float(n)) <= 1 for n, _ in nums[:4]):
            off = True
    for v in vals("clip-path"):
        if re.match(r"(?:inset\(\s*(?:100|50)%|circle\(\s*0|ellipse\(\s*0|polygon\(\s*0(?:px|%)?\s+0(?:px|%)?\s*,\s*0(?:px|%)?\s+0)", v):
            off = True
    clipped = any(v in ("hidden", "clip") for v in vals("overflow", "overflow-x", "overflow-y"))
    if clipped:
        for v in vals("width", "height", "max-width", "max-height", "inline-size", "block-size", "max-inline-size", "max-block-size"):
            d = _dim(v)
            if d is not None and d[1] in _ABS_PX and abs(d[0]) <= 1:
                off = True
    if off:
        kinds.add(HiddenKind.CSS_OFFSCREEN)
    return kinds


CLIP_TEXT = re.compile(r"background-clip\s*:\s*text", re.I)  # 背景を文字の形に切り抜く指定（-webkit- 付きも含む）


def hidden_kinds_from_style(style: str) -> set[HiddenKind]:
    """インライン style 属性から、人の目に見えなくなる指定を拾う（外部 CSS・クラスは評価できない）。"""
    return kinds_from_declarations(parse_declarations(style))


# --- <style> の単純なルール ----------------------------------------------------------------------------
MAX_STYLE_RULES = 2000  # 隠すルールの上限（巨大な CSS で時間とメモリを使わせない）
MAX_NEST = 6  # @media / @layer の入れ子を辿る深さ
_BRACES = re.compile(r"[{}]")
_NAME = r"(?:[\w-]|\\.)+"
_SIMPLE_SELECTOR = re.compile(rf"\s*(?P<tag>{_NAME}|\*)?(?P<rest>(?:[.#]{_NAME})*)\s*")
_SIMPLE_PART = re.compile(rf"([.#])({_NAME})")


_MEDIA_MIN = re.compile(r"\(\s*min-(?:width|height|device-width|device-height)\s*:\s*(" + _NUM + r")\s*(px|em|rem)?\s*\)")
_MEDIA_MAX = re.compile(r"\(\s*max-(?:width|height|device-width|device-height)\s*:\s*(" + _NUM + r")\s*(px|em|rem)?\s*\)")


def _media_cond_true(cond: str) -> bool:
    cond = cond.strip()
    if cond in ("all", "screen"):
        return True
    m = _MEDIA_MIN.fullmatch(cond)
    if m:  # どの画面でも満たす下限（100px 以下）
        return float(m.group(1)) * (16 if m.group(2) in ("em", "rem") else 1) <= 100
    m = _MEDIA_MAX.fullmatch(cond)
    if m:  # どの画面でも満たす上限（10000px 以上）
        return float(m.group(1)) * (16 if m.group(2) in ("em", "rem") else 1) >= 10000
    return False


def _media_always_true(prelude_lower: str) -> bool:
    """@media のクエリが、どの画面でも真（all・screen・どんな画面でも満たす幅条件）か。迷えば偽（＝評価しない）。"""
    for query in prelude_lower[len("@media") :].split(","):
        q = query.strip()
        if q.startswith("only "):
            q = q[5:]
        conds = re.split(r"\band\b", q)
        if conds and all(_media_cond_true(c) for c in conds):
            return True
    return False


@dataclass(frozen=True)
class _Rule:
    tag: str | None
    classes: frozenset[str]
    ident: str | None
    kinds: frozenset[HiddenKind]


class StyleRules:
    """文書内の <style> にある、タグ・クラス・id だけの単純なセレクタ（子孫・擬似クラス・属性セレクタ無し）のうち、
    要素を見えなくするもの。メディアクエリ内・複雑なセレクタ・外部 CSS は評価しない（限界）。"""

    def __init__(self, *, transparent: bool = True) -> None:
        self._transparent = transparent  # 規則の文字色の透明を隠しとして扱うか（文書が背景の切り抜きを使うなら False）
        self._rules: list[_Rule] = []
        self._by_key: dict[str, list[_Rule]] = {}

    def __bool__(self) -> bool:
        return bool(self._rules)

    def add_css(self, css: str, _depth: int = 0) -> None:
        if _depth > MAX_NEST:
            return
        css = strip_css_comments(css) if _depth == 0 else css
        n = len(css)
        i = 0
        while i < n and len(self._rules) < MAX_STYLE_RULES:
            j = css.find("{", i)
            if j < 0:
                break
            prelude = css[i:j].strip()
            end = self._matching_brace(css, j)
            if end < 0:
                end = n
            if prelude.startswith("@"):
                low = prelude.lower()
                if low.startswith("@layer") or (low.startswith("@media") and _media_always_true(low)):
                    self.add_css(css[j + 1 : end], _depth + 1)  # @layer と、常に真のメディアクエリは無条件に効く
                i = end + 1
                continue
            body = css[j + 1 : end]
            i = end + 1
            if "{" in body:
                continue  # CSS ネスト。評価しない
            kinds = frozenset(kinds_from_declarations(parse_declarations(body), transparent=self._transparent))
            if not kinds:
                continue
            for sel in prelude.split(","):
                rule = self._simple_rule(sel, kinds)
                if rule is not None:
                    self._rules.append(rule)
                    key = ("#" + rule.ident) if rule.ident else ("." + min(rule.classes)) if rule.classes else ("<" + (rule.tag or "*"))
                    self._by_key.setdefault(key, []).append(rule)

    @staticmethod
    def _matching_brace(css: str, open_idx: int) -> int:
        depth = 0
        for m in _BRACES.finditer(css, open_idx):
            depth += 1 if m.group() == "{" else -1
            if depth == 0:
                return m.start()
        return -1

    @staticmethod
    def _simple_rule(sel: str, kinds: frozenset[HiddenKind]) -> "_Rule | None":
        m = _SIMPLE_SELECTOR.fullmatch(sel)
        if not m or not (m.group("tag") or m.group("rest")):
            return None
        tag = css_unescape(m.group("tag")).lower() if m.group("tag") else None
        if tag == "*":
            if not m.group("rest"):
                return None  # 全要素へ掛かる規則（* {…}）は扱わない（文書全体が消えるため。ブラウザ側の判断に任せる）
            tag = None
        classes: set[str] = set()
        ident: str | None = None
        for kind, name in _SIMPLE_PART.findall(m.group("rest") or ""):
            if kind == ".":
                classes.add(css_unescape(name))
            elif ident is None:
                ident = css_unescape(name)
            elif ident != css_unescape(name):
                return None  # 2つの id を同時に満たす要素は無い
        return _Rule(tag, frozenset(classes), ident, kinds)

    def kinds_for(self, tag: str, classes: Iterable[str], ident: str) -> set[HiddenKind]:
        if not self._rules:
            return set()
        cls = set(classes)
        found: set[HiddenKind] = set()
        keys = [f"<{tag}", "<*"] + [f".{c}" for c in cls] + ([f"#{ident}"] if ident else [])
        for key in keys:
            for r in self._by_key.get(key, ()):
                if (r.tag is None or r.tag == tag) and r.classes <= cls and (r.ident is None or r.ident == ident):
                    found |= r.kinds
        return found
