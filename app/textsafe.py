"""可視テキストの安全判定。契約の検証・サニタイザ・引用検証で同じ基準を使うために1か所へ置く。

依存なし（標準ライブラリだけ）。
"""
import unicodedata

# ブロック境界（p/li/td/th/tr/h1-6/br）。sanitize が挿入し、引用検証の正規化でも除去しない（§5-1 S-02）。
BLOCK_SEP = "\u001e"
# 注入パターンに一致した区間の置換語（§5-2）。
INJECTION_PLACEHOLDER = "〔注入疑い〕"

_ALLOWED_CONTROLS = frozenset({"\n", "\t", BLOCK_SEP})
# Cc 制御・Cf 書式（ゼロ幅/bidi/タグ文字 U+E0000-E007F を含む）・Cs サロゲート・Co 私用領域・Zl/Zp 行段落区切り。
# Cn（未割当）は Python の Unicode 版で結果が変わるので判定に使わない。
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def is_unsafe_char(ch: str) -> bool:
    if ch in _ALLOWED_CONTROLS:
        return False
    return unicodedata.category(ch) in _UNSAFE_CATEGORIES


def find_unsafe(text: str) -> list[int]:
    """安全でない文字の位置（コードポイント単位）を返す。"""
    return [i for i, ch in enumerate(text) if is_unsafe_char(ch)]


def is_safe_text(text: str, *, allow_block_sep: bool = True) -> bool:
    if not allow_block_sep and BLOCK_SEP in text:
        return False
    return not find_unsafe(text)


def strip_unsafe(text: str) -> str:
    return "".join(ch for ch in text if not is_unsafe_char(ch))


def escape_for_display(text: str, limit: int) -> str:
    """画面・トレース用に、安全でない文字を \\uXXXX 表記へ、改行・境界を空白へ直し、limit 字で切る。"""
    out: list[str] = []
    for ch in text:
        if ch in ("\n", "\t", BLOCK_SEP):
            out.append(" ")
        elif is_unsafe_char(ch):
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: max(limit - 1, 0)] + "…"
