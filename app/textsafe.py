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


# ---- 本文のバイナリ判定と NUL の除去（要項モードの公開ページ。第11弾 追加指示3） ----------------------------------
# 実在の HTML（gzip で 272KB の告知ページ）の途中に NUL が1バイトだけ紛れていて、「1バイトでも NUL ならバイナリ」の判定で
# 読めなかった。バイナリの判定を次の3つに絞り、それ以外の NUL は取り除いて本文として扱う。判定と除去の定義はここだけ
# （S3 の SafeFetch が除去し、S2 の spec_read は同じ関数で判定だけを確かめる）。
BINARY_PREFIX_BYTES = 1024  # 先頭のこのバイト数に NUL があればバイナリ（画像・圧縮・実行形式の多くは先頭に NUL を持つ）
BINARY_NUL_MAX_RATIO = 0.01  # NUL の数が本文の 1% を超えたらバイナリ（ちょうど 1% は本文として扱う）
# 先頭の数バイトで形式が分かるもの（NUL を先頭に持たない PDF なども、text/html と名乗っても本文として扱わない）
BINARY_SIGNATURES: tuple[bytes, ...] = (
    b"%PDF-",  # PDF
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",  # ZIP（docx・xlsx を含む）
    b"\x1f\x8b",  # gzip の生データ
    b"GIF87a", b"GIF89a",  # GIF
    b"\xff\xd8\xff",  # JPEG
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # 旧形式の Office 文書
    b"\x7fELF",  # 実行形式
)  # fmt: skip


def looks_binary(body: bytes) -> bool:
    """本文がバイナリか（形式の署名で始まる・先頭 BINARY_PREFIX_BYTES に NUL・NUL の割合が BINARY_NUL_MAX_RATIO を超える）。"""
    if body.startswith(BINARY_SIGNATURES):
        return True
    if b"\x00" in body[:BINARY_PREFIX_BYTES]:
        return True
    return bool(body) and body.count(b"\x00") > len(body) * BINARY_NUL_MAX_RATIO


def strip_nul(body: bytes) -> bytes:
    """バイナリでない本文に紛れた NUL を取り除く（looks_binary が False の本文にだけ使う）。"""
    return body.replace(b"\x00", b"")
