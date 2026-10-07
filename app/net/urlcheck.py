"""URL の検証と取得スコープの照合（設計 §5-3「URL検証」「スコープ照合（S-07）」）。DNS 解決より前に行う。

方針は「読めたものだけ通す」。解釈が割れうる書き方（IP の別表記・userinfo・パーセントエンコードの . と /・`;`・
バックスラッシュ・二重スラッシュ）は、正規化して通すのでなく**拒否**する。通したものは、判定に使った正規化済みの
文字列（NormalizedUrl.url）をそのまま接続に使う＝検査した URL と接続する URL のずれを作らない。

ホストの IDNA は標準ライブラリ（2003）で行うが、ブラウザ（UTS 46）と結果が割れる畳み込み（ß→ss・点を作る文字など）は拒否する
（人が開く先と監査が取る先を割らない。_require_idna_agreement）。

拒否の理由は UrlReject のコード。公開面へ出るのは policy_id（P-SCOPE-01）だけで、コードは非公開ログとテスト用。
"""
import posixpath
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import quote, unquote_to_bytes

from app.contracts import UrlPrefix
from app.textsafe import is_unsafe_char

DEFAULT_MAX_URL_LENGTH = 2048


class UrlReject(StrEnum):
    EMPTY = "url.empty"
    TOO_LONG = "url.too_long"
    BAD_CHAR = "url.bad_char"  # 制御文字・空白・ゼロ幅・bidi など
    BACKSLASH = "url.backslash"
    SCHEME = "url.scheme"  # https 以外（http / file / javascript など）
    NO_AUTHORITY = "url.no_authority"
    USERINFO = "url.userinfo"
    PORT = "url.port"  # 443 以外・空のポート
    HOST_IPV6_LITERAL = "url.host_ipv6_literal"  # 角括弧・コロンが複数
    HOST_PERCENT = "url.host_percent"
    HOST_IDNA = "url.host_idna"
    HOST_FORMAT = "url.host_format"
    HOST_IP_LITERAL = "url.host_ip_literal"  # 10進・8進・16進・短縮形を含む IPv4 の別表記
    HOST_DOTLESS = "url.host_dotless"
    HOST_DENIED = "url.host_denied"  # localhost・*.local・*.internal など
    PATH_SEMICOLON = "url.path_semicolon"
    PATH_DOUBLE_SLASH = "url.path_double_slash"
    PATH_ESCAPE = "url.path_escape"  # %2e %2f %5c %3b %00 %25・不正なエスケープ・UTF-8 でない・制御文字
    QUERY_ESCAPE = "url.query_escape"
    SCOPE_OUT = "scope.out"  # 取得スコープの外（validate_url の責務ではなく in_scope が返す）


class UrlRejected(Exception):
    """validate_url の拒否。code だけが意味を持つ（メッセージに URL は入れない）。"""

    def __init__(self, code: UrlReject) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class NormalizedUrl:
    """検証済みで正規化した URL。接続にはこの url をそのまま使う。"""

    host: str  # 小文字・IDNA(punycode)・末尾ドット無し
    path: str  # posixpath.normpath 済み（元が "/" 終わりなら "/" を保つ）。先頭は必ず "/"
    query: str = ""  # "?" を含まない。空なら無し

    @property
    def url(self) -> str:
        return f"https://{self.host}{self.path}" + (f"?{self.query}" if self.query else "")


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")  # 最後のラベルがこれなら IPv4 の別表記として扱う（WHATWG の数値判定に倣う）
_DENIED_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")  # 後ろに16進2桁が無い %
# パスで拒否する（%2e . / %2f / / %5c \ / %3b ; / %00 と制御文字 / %25 二重エンコードの入口）
_PATH_FORBIDDEN_ESCAPE = re.compile(r"%(?:2[eEfF]|5[cC]|3[bB]|[01][0-9A-Fa-f]|7[fF]|25)")
_QUERY_CONTROL_ESCAPE = re.compile(r"%(?:[01][0-9A-Fa-f]|7[fF])")
_PATH_SAFE = "/%!$&'()*+,=:@-._~"  # 英数以外でそのまま通す文字（; は拒否済み、% は検証済みのエスケープ）
_QUERY_SAFE = "/%!$&'()*+,;=:@-._~?"


def _check_chars(url: str) -> None:
    for ch in url:
        if ch == "\\":
            raise UrlRejected(UrlReject.BACKSLASH)
        if ord(ch) <= 0x20 or ord(ch) == 0x7F or ch.isspace() or is_unsafe_char(ch):
            raise UrlRejected(UrlReject.BAD_CHAR)


_IDNA_DOTS = re.compile("[\u002e\u3002\uff0e\uff61]")  # idna コーデック（と UTS 46）が区切りとして読む点


def _require_idna_agreement(raw: str, encoded: str) -> None:
    """標準ライブラリの idna（IDNA 2003）が ASCII へ畳んだ結果が、ブラウザ（UTS 46）の読みと割れないことを確かめる。

    ASCII へ畳まれる文字のうち、2003 とブラウザで結果が割れるものがある（ß→ss・U+2024 や U+FE52 や ⒈ が点を作る、など。
    実測は tests/test_safefetch_adversarial.py A7）。割れたまま通すと、人が開く先と監査が取る先が別になる。
    畳みを「互換文字の正規化（NFKC＋小文字化）だけで説明できるもの」に限り、点の数が変わるもの・それ以外は拒否する。
    punycode（xn--）になった部分も、元の文字へ戻して同じ基準で確かめる。ASCII のホストとは衝突しないが、標準ライブラリの
    idna は Unicode の表の版で結果が変わる（10/7 実測: "STRA\u1e9eE" は 3.14 では "strasse"、3.13 では別の xn-- ホストになり、
    本番の 3.13 だけ検査をすり抜けた）。版に依らず「ブラウザより緩く読まない」を保つため、xn-- も対象にする。
    """
    src_labels = _IDNA_DOTS.split(raw)
    out_labels = encoded.split(".")
    if len(src_labels) != len(out_labels):  # 点でない文字が点に化けた
        raise UrlRejected(UrlReject.HOST_IDNA)
    for src, out in zip(src_labels, out_labels, strict=True):
        if src.isascii():
            continue
        want = unicodedata.normalize("NFKC", src).lower()
        if out.startswith("xn--"):
            try:
                got = out[4:].encode("ascii").decode("punycode")
            except UnicodeError as e:
                raise UrlRejected(UrlReject.HOST_IDNA) from e
            if got != want:
                raise UrlRejected(UrlReject.HOST_IDNA)
            continue
        if want != out.lower():
            raise UrlRejected(UrlReject.HOST_IDNA)


def _normalize_host(raw: str) -> str:
    try:
        host = raw.encode("idna").decode("ascii")  # NFKC・全角ドット・全角数字も ASCII へ（"１２７．０．０．１" → 127.0.0.1）
    except UnicodeError as e:
        raise UrlRejected(UrlReject.HOST_IDNA) from e
    if not raw.isascii():
        _require_idna_agreement(raw, host)
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]  # 末尾ドットは1つだけ除去
    if not host or len(host) > 253:
        raise UrlRejected(UrlReject.HOST_FORMAT)
    labels = host.split(".")
    for label in labels:
        if len(label) > 63 or not _LABEL.fullmatch(label):
            raise UrlRejected(UrlReject.HOST_FORMAT)  # 空ラベル（".."）・_・@ なども
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        raise UrlRejected(UrlReject.HOST_IP_LITERAL)
    if host == "localhost" or host.endswith(_DENIED_SUFFIXES):
        raise UrlRejected(UrlReject.HOST_DENIED)
    if len(labels) < 2:
        raise UrlRejected(UrlReject.HOST_DOTLESS)
    return host


def _normalize_path(raw: str) -> str:
    if ";" in raw:
        raise UrlRejected(UrlReject.PATH_SEMICOLON)
    if "//" in raw:
        raise UrlRejected(UrlReject.PATH_DOUBLE_SLASH)
    path = quote(raw, safe=_PATH_SAFE)  # 非 ASCII・" < > { } | ^ ` は UTF-8 のパーセントエンコードへ
    if _BAD_ESCAPE.search(path) or _PATH_FORBIDDEN_ESCAPE.search(path):
        raise UrlRejected(UrlReject.PATH_ESCAPE)
    try:
        decoded = unquote_to_bytes(path).decode("utf-8")  # 厳格に。過長 UTF-8（%c0%af など）はここで落ちる
    except UnicodeDecodeError as e:
        raise UrlRejected(UrlReject.PATH_ESCAPE) from e
    if any(is_unsafe_char(c) or (c.isspace() and c != " ") for c in decoded):  # %20 の空白は正当（他の空白類・不可視文字は拒否）
        raise UrlRejected(UrlReject.PATH_ESCAPE)
    norm = posixpath.normpath(path)
    if path.endswith("/") and norm != "/":
        norm += "/"  # normpath は末尾の "/" を落とす。スコープ "/fx/" の照合に必要
    return norm


def _normalize_query(raw: str) -> str:
    query = quote(raw, safe=_QUERY_SAFE)
    if _BAD_ESCAPE.search(query) or _QUERY_CONTROL_ESCAPE.search(query):
        raise UrlRejected(UrlReject.QUERY_ESCAPE)
    return query


def validate_url(url: str, *, max_length: int = DEFAULT_MAX_URL_LENGTH) -> NormalizedUrl:
    """URL を検証して正規化する。通らなければ UrlRejected。DNS は引かない。"""
    if not isinstance(url, str) or not url:
        raise UrlRejected(UrlReject.EMPTY)
    if len(url) > max_length:
        raise UrlRejected(UrlReject.TOO_LONG)
    _check_chars(url)

    scheme, sep, rest = url.partition(":")
    if not sep or scheme.lower() != "https":
        raise UrlRejected(UrlReject.SCHEME)
    if not rest.startswith("//"):
        raise UrlRejected(UrlReject.NO_AUTHORITY)
    rest = rest[2:].partition("#")[0]  # fragment は捨てる

    cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    authority, remainder = rest[:cut], rest[cut:]
    if not authority:
        raise UrlRejected(UrlReject.HOST_FORMAT)
    if "@" in authority:
        raise UrlRejected(UrlReject.USERINFO)
    if "[" in authority or "]" in authority or authority.count(":") > 1:
        raise UrlRejected(UrlReject.HOST_IPV6_LITERAL)
    if "%" in authority:
        raise UrlRejected(UrlReject.HOST_PERCENT)
    host_part = authority
    if ":" in authority:
        host_part, _, port = authority.partition(":")
        if port != "443":  # 空のポート・0443・8443 はすべて拒否。443 は明示されても URL からは落とす
            raise UrlRejected(UrlReject.PORT)
    host = _normalize_host(host_part)

    raw_path, _, raw_query = remainder.partition("?")
    path = _normalize_path(raw_path or "/")
    query = _normalize_query(raw_query)
    normalized = NormalizedUrl(host=host, path=path, query=query)
    if len(normalized.url) > max_length:  # パーセントエンコードで伸びた分
        raise UrlRejected(UrlReject.TOO_LONG)
    return normalized


def in_scope(url: NormalizedUrl, prefixes: Iterable[UrlPrefix]) -> bool:
    """取得スコープ（host＋パス接頭辞）に入るか。照合の定義は UrlPrefix.matches が唯一（Governor・Preset と共用）。"""
    return any(p.matches(url.host, url.path) for p in prefixes)

