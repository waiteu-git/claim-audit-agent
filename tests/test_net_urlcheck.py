"""URL 検証とスコープ照合（app/net/urlcheck.py）。DNS は引かない。

方針は「読めたものだけ通す」。解釈が割れる書き方は正規化して通さず、拒否する。通したものは、標準の URL パーサ
（urllib）が読んでも同じホスト・パスになることを確かめる（検査した URL と接続する URL のずれが無いこと）。
"""
import random
from urllib.parse import urlsplit

import pytest

from app.contracts import UrlPrefix
from app.net.urlcheck import NormalizedUrl, UrlReject, UrlRejected, in_scope, validate_url

H = "svc.example.invalid"


def _reject(url: str) -> UrlReject:
    with pytest.raises(UrlRejected) as ei:
        validate_url(url)
    return ei.value.code


@pytest.mark.parametrize(
    ("url", "expected_url"),
    [
        (f"https://{H}/fx/a", f"https://{H}/fx/a"),
        (f"https://{H}", f"https://{H}/"),
        (f"https://{H}?a=1", f"https://{H}/?a=1"),
        (f"HTTPS://{H.upper()}/fx/a", f"https://{H}/fx/a"),  # scheme・host は大文字小文字を区別しない
        (f"https://{H}./fx/a", f"https://{H}/fx/a"),  # 末尾ドットは除去
        (f"https://{H}:443/fx/a", f"https://{H}/fx/a"),  # 443 の明示は許し、URL からは落とす
        (f"https://{H}/fx/a#frag", f"https://{H}/fx/a"),  # fragment は除去
        (f"https://{H}/fx/./a", f"https://{H}/fx/a"),
        (f"https://{H}/fx/x/../a", f"https://{H}/fx/a"),
        (f"https://{H}/fx/", f"https://{H}/fx/"),  # 末尾の / を保つ（スコープ /fx/ の照合に必要）
        (f"https://{H}/fx/.", f"https://{H}/fx"),
        (f"https://{H}/日本語/", f"https://{H}/%E6%97%A5%E6%9C%AC%E8%AA%9E/"),  # 非 ASCII は UTF-8 のパーセントエンコードへ
        (f"https://{H}/a%20b", f"https://{H}/a%20b"),
        (f"https://{H}/?next=%2Fa&x=%25", f"https://{H}/?next=%2Fa&x=%25"),  # クエリの %2f・%25 は許す（スコープに無関係）
        ("https://münchen.example/x", "https://xn--mnchen-3ya.example/x"),  # IDNA
        ("https://１２３.example.invalid/", "https://123.example.invalid/"),  # 全角数字は NFKC で ASCII へ
    ],
)
def test_accepted_urls_are_normalized(url: str, expected_url: str):
    assert validate_url(url).url == expected_url


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("", UrlReject.EMPTY),
        ("https://" + "a" * 2100 + ".example/", UrlReject.TOO_LONG),
        (f"https://{H}/ x", UrlReject.BAD_CHAR),
        (f" https://{H}/", UrlReject.BAD_CHAR),
        (f"https://{H}/\t", UrlReject.BAD_CHAR),
        (f"https://{H}/a\r\nHost: x", UrlReject.BAD_CHAR),
        (f"https://{H}/​x", UrlReject.BAD_CHAR),  # ゼロ幅
        (f"https://{H}/‮x", UrlReject.BAD_CHAR),  # bidi
        (f"https://{H}/ x", UrlReject.BAD_CHAR),  # 非改行スペース
        (f"https://{H}/\x00", UrlReject.BAD_CHAR),
        (f"https://{H}\\@evil.example/", UrlReject.BACKSLASH),
        (f"https://{H}/fx\\..\\a", UrlReject.BACKSLASH),
        (f"http://{H}/", UrlReject.SCHEME),
        ("file:///etc/passwd", UrlReject.SCHEME),
        ("javascript:alert(1)", UrlReject.SCHEME),
        (f"ftp://{H}/", UrlReject.SCHEME),
        (f"//{H}/fx/a", UrlReject.SCHEME),
        (f"{H}/fx/a", UrlReject.SCHEME),
        (f"https:{H}/", UrlReject.NO_AUTHORITY),
        (f"https:/{H}/", UrlReject.NO_AUTHORITY),
        ("https:///fx/a", UrlReject.HOST_FORMAT),
        (f"https://user@{H}/", UrlReject.USERINFO),
        (f"https://user:pw@{H}/", UrlReject.USERINFO),
        (f"https://{H}@evil.example/", UrlReject.USERINFO),
        (f"https://{H}:8443/", UrlReject.PORT),
        (f"https://{H}:80/", UrlReject.PORT),
        (f"https://{H}:/", UrlReject.PORT),
        (f"https://{H}:0443/", UrlReject.PORT),
        (f"https://{H}:443x/", UrlReject.PORT),
        ("https://[::1]/", UrlReject.HOST_IPV6_LITERAL),
        ("https://[2606:4700::1111]/", UrlReject.HOST_IPV6_LITERAL),
        ("https://::1/", UrlReject.HOST_IPV6_LITERAL),
        (f"https://svc%2eexample.invalid/", UrlReject.HOST_PERCENT),
        ("https://%31%32%37.0.0.1/", UrlReject.HOST_PERCENT),
        ("https://127.0.0.1/", UrlReject.HOST_IP_LITERAL),
        ("https://169.254.169.254/", UrlReject.HOST_IP_LITERAL),
        ("https://2130706433/", UrlReject.HOST_IP_LITERAL),  # 10進
        ("https://0x7f000001/", UrlReject.HOST_IP_LITERAL),  # 16進
        ("https://0x7f.0x0.0x0.0x1/", UrlReject.HOST_IP_LITERAL),
        ("https://0177.0.0.1/", UrlReject.HOST_IP_LITERAL),  # 8進
        ("https://017700000001/", UrlReject.HOST_IP_LITERAL),
        ("https://127.1/", UrlReject.HOST_IP_LITERAL),  # 短縮形
        ("https://127.0.1/", UrlReject.HOST_IP_LITERAL),
        ("https://0/", UrlReject.HOST_IP_LITERAL),
        ("https://１２７．０．０．１/", UrlReject.HOST_IP_LITERAL),  # 全角
        ("https://127。0。0。1/", UrlReject.HOST_IP_LITERAL),  # 句点の別表記
        ("https://127.0.0.1./", UrlReject.HOST_IP_LITERAL),  # 末尾ドット付き
        ("https://a.b.c.1/", UrlReject.HOST_IP_LITERAL),  # 数字で終わる名前も拒否（実在の TLD は数字で終わらない）
        ("https://localhost/", UrlReject.HOST_DENIED),
        ("https://LOCALHOST./", UrlReject.HOST_DENIED),
        ("https://a.localhost/", UrlReject.HOST_DENIED),
        ("https://printer.local/", UrlReject.HOST_DENIED),
        ("https://metadata.google.internal/", UrlReject.HOST_DENIED),
        ("https://x.internal/", UrlReject.HOST_DENIED),
        ("https://x.home.arpa/", UrlReject.HOST_DENIED),
        ("https://intranet/", UrlReject.HOST_DOTLESS),
        ("https://a..b.example/", UrlReject.HOST_IDNA),
        ("https://-a.example/", UrlReject.HOST_FORMAT),
        ("https://a_b.example/", UrlReject.HOST_FORMAT),
        ("https://exa＠mple.example/", UrlReject.HOST_FORMAT),  # 全角 @ は NFKC で @ になるが、ホストとして不正
        (f"https://{'a' * 64}.example/", UrlReject.HOST_IDNA),
        (f"https://{H}/fx;a=1/x", UrlReject.PATH_SEMICOLON),
        (f"https://{H}/fx//x", UrlReject.PATH_DOUBLE_SLASH),
        (f"https://{H}/fx/%2e%2e/x", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%2E%2E/x", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/..%2fx", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/..%2Fx", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/..%5cx", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%3bx", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%00", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%0d%0a", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%7f", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%252e%252e/x", UrlReject.PATH_ESCAPE),  # 二重エンコード
        (f"https://{H}/fx/%zz", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%", UrlReject.PATH_ESCAPE),
        (f"https://{H}/fx/%c0%af", UrlReject.PATH_ESCAPE),  # 過長 UTF-8 の /
        (f"https://{H}/fx/%ff", UrlReject.PATH_ESCAPE),  # UTF-8 として不正
        (f"https://{H}/fx/%e2%80%ae", UrlReject.PATH_ESCAPE),  # bidi をエンコードして隠す
        (f"https://{H}/?a=%zz", UrlReject.QUERY_ESCAPE),
        (f"https://{H}/?a=%00", UrlReject.QUERY_ESCAPE),
    ],
)
def test_rejected_urls_report_a_specific_code(url: str, code: UrlReject):
    assert _reject(url) is code


def test_non_string_input_is_rejected_not_crashed():
    for bad in (None, 123, b"https://x.example/"):
        with pytest.raises(UrlRejected):
            validate_url(bad)  # type: ignore[arg-type]


# ---------------------------------------------------------------- スコープ照合
PREFIXES = (
    UrlPrefix(host="lp.example.invalid", path_prefix="/event", exact=True),
    UrlPrefix(host=H, path_prefix="/", exact=True),
    UrlPrefix(host=H, path_prefix="/fx/"),
    UrlPrefix(host="docs.example.invalid", path_prefix="/guide"),
)


@pytest.mark.parametrize(
    ("url", "inside"),
    [
        ("https://lp.example.invalid/event", True),
        ("https://lp.example.invalid/event?lang=ja", True),  # exact はパスだけを見る
        ("https://lp.example.invalid/event/", False),  # exact は完全一致のみ
        ("https://lp.example.invalid/event/x", False),
        ("https://lp.example.invalid/events", False),
        ("https://lp.example.invalid/", False),
        (f"https://{H}/", True),  # 自サービスの "/"（完全一致）
        (f"https://{H}/index.html", False),
        (f"https://{H}/fx/", True),
        (f"https://{H}/fx/a/b", True),
        (f"https://{H}/fx", False),  # "/fx/" の配下は "/fx" を含まない
        (f"https://{H}/fxx/", False),  # セグメント境界
        (f"https://{H}/fx/../api/run", False),  # 正規化後は /api/run
        (f"https://{H}/fx/../fx/a", True),  # 正規化後に収まるなら通す（その文字列で接続する）
        (f"https://{H}/api/run", False),
        (f"https://{H}.attacker.example/fx/a", False),  # ホストの後ろに足した別ドメイン
        (f"https://attacker.{H}/fx/a", False),  # サブドメインはスコープ外
        ("https://docs.example.invalid/guide", True),  # 非 exact の接頭辞は自身と配下
        ("https://docs.example.invalid/guide/a", True),
        ("https://docs.example.invalid/guidebook", False),
        ("https://docs.example.invalid/", False),
        ("https://other.example.invalid/", False),
    ],
)
def test_scope_matching_on_normalized_url(url: str, inside: bool):
    assert in_scope(validate_url(url), PREFIXES) is inside


def test_empty_scope_allows_nothing():
    assert in_scope(validate_url(f"https://{H}/fx/a"), ()) is False


# ---------------------------------------------------------------- 性質（ファジング）
_ALPHABET = list("abcAZ09.-_:/\\?#@%[]~;=&+*!'()$, ") + [
    "é", "日", "．", "。", "＠", "／", "​", "‮", "\x00", "\n", "%2e", "%2f", "%5c", "%25", "%c0%af", "0x", "..", "//",
]


def _random_url(rng: random.Random) -> str:
    parts = rng.choice(["https://", "https://", "https://", "http://", "https:", "//", ""])
    host = rng.choice([H, "lp.example.invalid", "127.0.0.1", "0x7f.1", "a.b.c", "x"])
    tail = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 24)))
    glue = rng.choice(["", "/", "/fx/", ":443/", "@", ":", "/fx/..", "?"])
    return parts + host + glue + tail


def test_fuzz_only_urlrejected_or_a_url_every_parser_reads_the_same():
    """8000本の乱数 URL。例外は UrlRejected だけ。通ったものは urllib が読んでも同じホスト・パス（差分が無い）。"""
    rng = random.Random(20261002)
    accepted = 0
    for _ in range(8000):
        url = _random_url(rng)
        try:
            n = validate_url(url)
        except UrlRejected:
            continue
        accepted += 1
        out = n.url
        assert out.isascii() and not any(c in out for c in "\\ \t\r\n\x00")
        sp = urlsplit(out)
        assert (sp.scheme, sp.hostname, sp.port, sp.username) == ("https", n.host, None, None)
        assert sp.path == n.path and sp.query == n.query and sp.fragment == ""
        assert "//" not in n.path and ";" not in n.path and ".." not in n.path.split("/")
        assert validate_url(out) == n  # 冪等（正規化済みの文字列を再検証しても同じ）
    assert accepted > 100  # 「全部拒否」で緑になっていない


def test_normalized_url_is_frozen_value_object():
    n = NormalizedUrl(host=H, path="/fx/a", query="x=1")
    assert n.url == f"https://{H}/fx/a?x=1"
    with pytest.raises(AttributeError):
        n.host = "x"  # type: ignore[misc]


def test_idna_agreement_is_checked_for_punycode_output_too_independent_of_the_python_version():
    """回帰（10/7）: 標準ライブラリの idna は Unicode の表の版で結果が変わる。"STRA\\u1e9eE" は 3.14 では "strasse"、3.13 では別の
    xn-- ホストになり、「xn-- は対象外」だった旧実装は本番の 3.13 だけ検査をすり抜けた。コーデックの出力を直接与えて、版に依らず確かめる。"""
    from app.net.urlcheck import UrlReject, UrlRejected, _require_idna_agreement

    with pytest.raises(UrlRejected) as e:  # 3.13 のコーデックの出力（元の ẞ を残した別のホスト）
        _require_idna_agreement("STRAẞE.example.invalid", "xn--strae-301b.example.invalid")
    assert e.value.code is UrlReject.HOST_IDNA
    with pytest.raises(UrlRejected):  # punycode として読めない出力は拒否
        _require_idna_agreement("münchen.example.invalid", "xn--!!.example.invalid")
    _require_idna_agreement("münchen.example.invalid", "xn--mnchen-3ya.example.invalid")  # 本物の IDN は通す
    _require_idna_agreement("テスト.example.invalid", "xn--zckzah.example.invalid")  # 日本語のラベルも通す
