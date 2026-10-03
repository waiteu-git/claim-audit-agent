"""統合担当の試験（その1）: 別々のモジュールが「同じ事実」を別実装で判定している箇所が、割れないこと。

並行で作られたモジュールは、それぞれ単体の試験は緑でも、同じ入力に違う答えを返すと、人が見るもの（ブラウザ）と
こちらが読むものが食い違う。食い違いが実害になるのは次の2か所だった:

  * 文字コード: T4 の sanitize（本文を読む）と T9 の html_signals（ログイン画面を探す）。
  * リンクのスコープ判定: T4 の sanitize（リンク表の in_scope）と T3 の SafeFetch（取得時の検査）。

どちらも「定義を1か所にする」ことで直し、この試験は再び割れないことを固定する。
"""
import codecs

import pytest

from app.checks.html_signals import decode_body as probe_decode
from app.checks.http_probe import observe_probe
from app.contracts import ObsCode, ObsOutcome, UrlPrefix
from app.ingest.sanitize import decode_body as ingest_decode
from app.ingest.sanitize import link_in_scope
from app.net.urlcheck import UrlRejected, in_scope, validate_url
from app.net.vectors import SVC_HOST, VECTOR_PREFIXES
from tests.fetch_fakes import SUB_URL, make_result

# --- 文字コード --------------------------------------------------------------------------------------------

LOGIN_FORM = '<form action="/session" method="post"><input type="text" name="u"><input type="password" name="p"></form>'
LOGIN_PAGE = (
    "<html><head>{meta}<title>Console</title></head><body><h1>Sign in</h1>"
    "<p>Enter your access code to continue to the dashboard and see the status of this workspace.</p>"
    + LOGIN_FORM
    + "</body></html>"
)
META_U16 = '<meta charset="utf-16">'
META_U16_HTTP = '<meta http-equiv="Content-Type" content="text/html; charset=utf-16le">'


def _page(meta: str = "", pad: int = 0) -> str:
    return LOGIN_PAGE.format(meta=meta).replace("<title>", "<!--" + "x" * pad + "--><title>")


def _decode_cases() -> list[tuple[str, bytes, str | None]]:
    """(名前, 本文, Content-Type)。ブラウザの読み方が割れやすい組み合わせを集める。"""
    utf8 = _page().encode()
    ja = "<html><body>提出物の説明は八百字以内。ログイン<input type=password></body></html>"
    cases: list[tuple[str, bytes, str | None]] = [
        ("plain utf-8", utf8, None),
        ("header utf-8", utf8, "text/html; charset=utf-8"),
        ("header UTF-8 quoted", utf8, 'text/html; charset="UTF-8"'),
        ("meta utf-16 only (UTF-8 body)", _page(META_U16).encode(), None),
        ("meta utf-16le http-equiv (UTF-8 body)", _page(META_U16_HTTP).encode(), None),
        ("meta utf-16 + header utf-8", _page(META_U16).encode(), "text/html; charset=utf-8"),
        ("header utf-16 (UTF-8 body, no BOM)", _page().encode(), "text/html; charset=utf-16"),
        ("BOM utf-8 + header sjis", codecs.BOM_UTF8 + _page().encode(), "text/html; charset=shift_jis"),
        ("BOM utf-16le", codecs.BOM_UTF16_LE + _page().encode("utf-16-le"), None),
        ("BOM utf-16be + header utf-8", codecs.BOM_UTF16_BE + _page().encode("utf-16-be"), "text/html; charset=utf-8"),
        ("BOM-less utf-16le + header utf-16", _page().encode("utf-16-le"), "text/html; charset=utf-16"),
        ("shift_jis header", ja.encode("shift_jis"), "text/html; charset=Shift_JIS"),
        ("shift_jis meta", ja.replace("<body>", '<meta charset="shift_jis"><body>').encode("shift_jis"), None),
        ("euc-jp header", ja.encode("euc_jp"), "text/html; charset=euc-jp"),
        ("windows-1252 header", "<p>café</p>".encode("cp1252"), "text/html; charset=windows-1252"),
        ("replacement label hz-gb-2312", utf8, "text/html; charset=hz-gb-2312"),
        ("replacement label iso-2022-kr (meta)", _page('<meta charset="iso-2022-kr">').encode(), None),
        ("utf-7 header", utf8, "text/html; charset=utf-7"),
        ("unicode_escape header", utf8, "text/html; charset=unicode_escape"),
        ("unknown label", utf8, "text/html; charset=x-nope"),
        ("meta inside a comment", _page("<!-- " + META_U16 + " -->").encode(), None),
        ("meta after 1024 bytes", _page(META_U16, pad=1500).encode(), None),
        ("meta after 2100 bytes", _page(META_U16, pad=2300).encode(), None),
        ("empty", b"", None),
        ("content-type empty string", utf8, ""),
    ]
    return cases


@pytest.mark.parametrize("name,body,content_type", _decode_cases(), ids=[c[0] for c in _decode_cases()])
def test_the_two_charset_readers_agree(name: str, body: bytes, content_type: str | None):
    """sanitize（本文を読む側）と html_signals（ログイン画面を探す側）が、同じ本文を同じ文字列に読む。"""
    assert probe_decode(body, content_type) == ingest_decode(body, content_type or "")


def test_a_login_page_declaring_utf16_in_meta_is_not_reported_as_open():
    """ブラウザは meta で宣言された UTF-16 を UTF-8 として読む（WHATWG）。UTF-8 のログイン画面に
    `<meta charset=utf-16>` を足すだけで password 欄が読めなくなり、「誰でも開ける」と強く言ってしまった（統合時に再現）。"""
    body = _page(META_U16).encode()
    for headers in ({"content-type": "text/html"}, {"content-type": "text/html; charset=utf-8"}, {}):
        obs = observe_probe(make_result(SUB_URL, headers=headers, body=body), obs_id="O1")
        assert obs.code is ObsCode.AUTH_WALL and obs.outcome is ObsOutcome.FAIL, headers
        assert obs.facts["has_password_input"] is True, headers


# --- リンクのスコープ判定 ------------------------------------------------------------------------------------

H = SVC_HOST
_HREFS = [
    f"https://{H}/",
    f"https://{H}/fx/a",
    f"https://{H}/fx/a/",
    f"https://{H}/fx/a?q=1",
    f"https://{H}/fx/a#frag",
    f"https://{H}:443/fx/a",
    f"https://{H.upper()}/fx/a",
    f"https://{H}./fx/a",
    f"https://{H}/fx/../fx/a",
    f"https://{H}/fx/./a",
    f"https://{H}/fx/../etc/passwd",
    f"https://{H}/fx//a",
    f"https://{H}/fx/日本語",
    f"https://{H}/fx/%E6%97%A5%E6%9C%AC",  # 日本語のパス（SafeFetch は通す）
    f"https://{H}/fx/a%20b",
    f"https://{H}/fx/%41",
    f"https://{H}/fx/%2e%2e/x",
    f"https://{H}/fx/%2f",
    f"https://{H}/fx/%5c",
    f"https://{H}/fx/%00",
    f"https://{H}/fx/a;x",
    f"https://{H}/fx/a\\b",
    f"https://{H}/fx/a\tb",
    f"https://{H}/fx/​",
    f"https://{H}/fx/" + "a" * 3000,
    f"https://{H.replace('.', chr(0x2024))}/fx/a",  # ONE DOT LEADER: IDNA 2003 は点に畳むがブラウザは別ホスト
    "https://svc.exaßmple.invalid/fx/a",
    "https://１２７．０．０．１/fx/a",
    f"http://{H}/fx/a",
    f"https://user@{H}/fx/a",
    f"https://{H}:8443/fx/a",
    f"https:///{H}/fx/a",
    f"///{H}/fx/a",
    "https://lp.example.invalid/event",
    "https://lp.example.invalid/event/x",
    "https://svc2.example.invalid/anything",
    "https://other.example.invalid/fx/a",
]


@pytest.mark.parametrize("href", _HREFS, ids=[h[:60] for h in _HREFS])
def test_link_table_scope_flag_matches_what_safefetch_would_accept(href: str):
    """リンク表の in_scope=True は、取得時の検査（validate_url→スコープ照合）を通る URL にだけ付く。逆も同じ
    （通る URL を False にすると、Planner が取れるはずのリンクを選べない）。"""
    try:
        expected = in_scope(validate_url(href), VECTOR_PREFIXES)
    except UrlRejected:
        expected = False
    assert link_in_scope(href, VECTOR_PREFIXES) is expected


def test_link_scope_flag_is_false_without_a_scope():
    assert link_in_scope(f"https://{H}/fx/a", ()) is False
    assert link_in_scope(f"https://{H}/fx/a", (UrlPrefix(host="other.example.invalid", path_prefix="/"),)) is False
