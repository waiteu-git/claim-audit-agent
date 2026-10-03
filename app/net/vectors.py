"""SafeFetch の敵対ベクタ（設計 §5-3「ベクタ」）。pytest と共用するデータだけを持つ（通信も判定も実装しない）。

  * ホストは全て *.example.invalid（実在しない）。IP は「公開として扱われる値」と、拒否されるべき値だけ。
  * tier 2 = Gate2 の「ベクタ15本」（実際は 15 を超えて持つ）。tier 3 = Gate3 までに全部（S-07 の7本のうち配信側の
    1本＝「クエリ付き /fx/ は 404」は T12 の責務なのでここには無い）。
  * Governor・モデルの側のベクタ（23回目のモデル呼び出し・同一呼び出し2回目・存在しない link_id）は T7 の責務。
  * POSITIVE_CONTROLS は「通るべき」書き方。拒否の試験が「何も通らない環境だから緑」になっていないことの対照。

ハーネス（tests/test_safefetch_vectors.py）が Vector から偽の DNS と偽のサイトを組み、SafeFetch に流して Expect と照合する。
"""
from collections.abc import Mapping
from dataclasses import dataclass, field

from app.contracts import FetchLimit, FetchOutcome, PolicyId, UrlPrefix

LP_HOST = "lp.example.invalid"
SVC_HOST = "svc.example.invalid"
SVC2_HOST = "svc2.example.invalid"
PUBLIC_IP = "8.8.8.8"  # 公開として扱われる値（偽の DNS が返す。実際には接続しない）
PUBLIC_IP_2 = "8.8.4.4"
PRIVATE_IP = "10.0.0.5"
METADATA_IP = "169.254.169.254"

# 取得スコープ（config の ALLOWED_PREFIXES と同じ形）。LP は正確な1URL、自サービスは "/"（完全一致）と "/fx/" 配下。
VECTOR_PREFIXES: tuple[UrlPrefix, ...] = (
    UrlPrefix(host=LP_HOST, path_prefix="/event", exact=True),
    UrlPrefix(host=SVC_HOST, path_prefix="/", exact=True),
    UrlPrefix(host=SVC_HOST, path_prefix="/fx/"),
    UrlPrefix(host=SVC2_HOST, path_prefix="/"),
)

# 偽の DNS の既定。ベクタの dns が上書きする。値は「呼び出し回数ごとの応答」の並び（最後の応答が以降も続く）。
DEFAULT_DNS: dict[str, tuple[tuple[str, ...], ...]] = {
    LP_HOST: ((PUBLIC_IP,),),
    SVC_HOST: ((PUBLIC_IP,),),
    SVC2_HOST: ((PUBLIC_IP_2,),),
}

# 遅い応答のベクタ用の短い時間（本番は 3 / 8 / 4 秒）。Reply の遅延はこれを基準に決めてある。
VECTOR_LIMITS_KW: dict[str, float | int] = {"connect_timeout_s": 0.5, "total_timeout_s": 0.6, "sock_read_timeout_s": 0.25}

_HTML = (("Content-Type", "text/html; charset=utf-8"),)


@dataclass(frozen=True)
class Reply:
    """偽のサイトが返す応答。body / repeat / infinite のどれか（無ければ空）。"""

    status: int = 200
    headers: tuple[tuple[str, str], ...] = _HTML
    body: bytes = b""
    repeat: tuple[bytes, int] | None = None  # (塊, 回数)。巨大な本文を少ないメモリで作る
    prefix: bytes = b""  # infinite の前に送る生バイト
    infinite: bytes | None = None  # この塊を読み手が止めるまで送り続ける（chunked）
    gzip: bool = False  # body / repeat を gzip して送る
    chunked: bool = False  # Content-Length でなく Transfer-Encoding: chunked で送る（終わりのある本文）
    chunk_size: int = 16 * 1024  # chunked の1塊の長さ（1 にすると「1バイトずつ刻む」応答になる）
    chunk_ext: int = 0  # chunked の各塊の長さ行に付ける chunk-extension の長さ（本文は増えず、受信バイトだけが増える）
    informational: int = 0  # 本物の応答の前に送る「100 Continue」の数（1xx の洪水）
    content_length: int | None = None  # 実際と違う長さを宣言する（None なら実長）
    first_byte_delay_s: float = 0.0
    chunk_delay_s: float = 0.0


@dataclass(frozen=True)
class Expect:
    outcome: FetchOutcome
    blocked_policy: PolicyId | None = None  # outcome=BLOCKED の時
    status: int | None = None
    hop_policy: PolicyId | None = None  # 追跡しなかった最後のホップの blocked_policy
    note: str | None = None  # notes のどれかに部分一致する内部理由コード
    limit_hit: FetchLimit | None = None
    truncated: bool = False
    body_max: int | None = None  # 本文の長さの上限（打切りの確認）
    connects: tuple[str, ...] | None = None  # 接続した IP（順序どおり・全部）。None なら見ない
    resolver_calls: Mapping[str, int] | None = None  # ホストごとの名前解決の回数


@dataclass(frozen=True)
class Vector:
    id: str
    tier: int  # 2 = Gate2、3 = Gate3 まで
    desc: str
    url: str
    expect: Expect
    dns: Mapping[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)  # DEFAULT_DNS を上書き
    replies: Mapping[str, Reply] = field(default_factory=dict)  # "host/path" → 応答
    never_connect: tuple[str, ...] = ()  # この IP へ接続してはいけない
    limits_kw: Mapping[str, float | int] = field(default_factory=dict)  # FetchLimits の上書き


_SCOPE = PolicyId.SCOPE
_IP = PolicyId.SSRF_IP


def _blocked(policy: PolicyId, note: str) -> Expect:
    """最初の URL の拒否。接続は0回。スコープ・URL 検証の拒否は DNS も引かない（名前を漏らさない）。IP 検査の拒否は1回だけ引く。"""
    calls: dict[str, int] = {} if policy is _SCOPE else {SVC_HOST: 1}
    return Expect(outcome=FetchOutcome.BLOCKED, blocked_policy=policy, note=note, connects=(), resolver_calls=calls)


# 標準の CGNAT 帯のアドレス（ドット表記のリテラルを避けて組み立てる理由は app/net/ipcheck.py の _dq を参照）
_CGNAT_IP = ".".join(("100", "64", "0", "1"))
_PAGE_URL = f"https://{SVC_HOST}/fx/a"
_PAGE_KEY = f"{SVC_HOST}/fx/a"
_OK_PAGE = Reply(body=b"<html><body>ok</body></html>")

_ALL: tuple[Vector, ...] = (
    # ---- tier 2: URL 検証（DNS の前。接続は0回）
    Vector("url-metadata-ip-literal", 2, "メタデータ IP の直書き", f"https://{METADATA_IP}/computeMetadata/v1/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-metadata-hostname", 2, "メタデータのホスト名", "https://metadata.google.internal/computeMetadata/v1/", _blocked(_SCOPE, "url.host_denied")),
    Vector("url-loopback-v4", 2, "127.0.0.1", "https://127.0.0.1/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-loopback-v6", 2, "[::1]", "https://[::1]/", _blocked(_SCOPE, "url.host_ipv6_literal")),
    Vector("url-ip-decimal", 2, "10進表記の IP（127.0.0.1）", "https://2130706433/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-ip-hex", 2, "16進表記の IP（127.0.0.1）", "https://0x7f000001/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-ip-octal", 2, "8進表記の IP（127.0.0.1）", "https://0177.0.0.1/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-userinfo", 2, "userinfo でホストを偽装", f"https://{SVC_HOST}@evil.example.invalid/fx/a", _blocked(_SCOPE, "url.userinfo")),
    Vector("url-port-8443", 2, "443 以外のポート", f"https://{SVC_HOST}:8443/fx/a", _blocked(_SCOPE, "url.port")),
    Vector("url-file-scheme", 2, "file スキーム", "file:///etc/passwd", _blocked(_SCOPE, "url.scheme")),
    Vector("scope-outside-host", 2, "取得スコープ外のホスト", "https://other.example.invalid/", _blocked(_SCOPE, "scope.out")),
    # ---- tier 2: スコープ内 → 転送で内部へ（追跡せず Location だけ残す）
    Vector(
        "redirect-to-metadata-literal", 2, "スコープ内 → 302 → メタデータ IP の直書き", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:url.host_ip_literal", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", f"https://{METADATA_IP}/computeMetadata/v1/"),))},
        never_connect=(METADATA_IP,),
    ),
    Vector(
        "redirect-to-host-resolving-private", 2, "スコープ内 → 302 → スコープ内だが私有 IP に解決されるホスト", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_IP, note="hop1:ip.private", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1, SVC2_HOST: 1}),
        dns={SVC2_HOST: ((PRIVATE_IP,),)},
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", f"https://{SVC2_HOST}/x"),))},
        never_connect=(PRIVATE_IP,),
    ),
    # ---- tier 2: DNS の応答
    Vector(
        "dns-mixed-public-private", 2, "公開 IP と私有 IP の混在応答（全体拒否）", _PAGE_URL,
        _blocked(_IP, "ip.private"), dns={SVC_HOST: ((PUBLIC_IP, PRIVATE_IP),)}, never_connect=(PUBLIC_IP, PRIVATE_IP),
    ),
    Vector(
        "dns-v4-mapped-metadata", 2, "::ffff:169.254.169.254（IPv4 射影でメタデータ）", _PAGE_URL,
        _blocked(_IP, "v4mapped>ip.metadata"), dns={SVC_HOST: (("::ffff:169.254.169.254",),)}, never_connect=("::ffff:169.254.169.254",),
    ),
    Vector(
        "dns-rebinding-public-then-private", 2, "名前解決の2回目に私有 IP を返す（ピン留めで再解決しない）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        dns={SVC_HOST: ((PUBLIC_IP,), (PRIVATE_IP,))},
        replies={_PAGE_KEY: _OK_PAGE},
        never_connect=(PRIVATE_IP,),
    ),
    # ---- tier 2: 本文・時間・種別
    Vector(
        "body-gzip-bomb", 2, "gzip 爆弾（展開後 64MiB）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=200, truncated=True, limit_hit=FetchLimit.DECODED_SIZE, body_max=1024 * 1024),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "gzip")), repeat=(b"\x00" * 65536, 1024), gzip=True)},
    ),
    Vector(
        "body-huge-content-length", 2, "Content-Length が 3MB 超（読む前に拒否）", _PAGE_URL,
        Expect(outcome=FetchOutcome.TOO_LARGE, status=200, limit_hit=FetchLimit.CONTENT_LENGTH, body_max=0),
        replies={_PAGE_KEY: Reply(body=b"<html>", content_length=10 * 1024 * 1024)},
    ),
    Vector(
        "body-slow-drip", 2, "遅い応答（1バイトずつ。全体の期限で止める）", _PAGE_URL,
        Expect(outcome=FetchOutcome.TIMEOUT, limit_hit=FetchLimit.TOTAL_TIMEOUT),
        replies={_PAGE_KEY: Reply(infinite=b"x", chunk_delay_s=0.1)},
    ),
    Vector(
        "type-octet-stream", 2, "許可リスト外の Content-Type", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, body_max=0),
        replies={_PAGE_KEY: Reply(headers=(("Content-Type", "application/octet-stream"),), body=b"\x00\x01\x02")},
    ),
    # ---- tier 3: S-07（スコープ照合の回避）
    Vector("s07-dotdot-out-of-scope", 3, "/fx/../api/run（正規化するとスコープ外）", f"https://{SVC_HOST}/fx/../api/run", _blocked(_SCOPE, "scope.out")),
    Vector("s07-encoded-dotdot", 3, "/fx/%2e%2e/api/run", f"https://{SVC_HOST}/fx/%2e%2e/api/run", _blocked(_SCOPE, "url.path_escape")),
    Vector("s07-encoded-slash", 3, "/fx/..%2fapi/run", f"https://{SVC_HOST}/fx/..%2fapi/run", _blocked(_SCOPE, "url.path_escape")),
    Vector("s07-prefix-not-segment", 3, "/fxx/（セグメント境界で一致しない）", f"https://{SVC_HOST}/fxx/", _blocked(_SCOPE, "scope.out")),
    Vector("s07-host-suffix-confusion", 3, "スコープのホストを前に置いた別ドメイン", f"https://{SVC_HOST}.attacker.example/fx/a", _blocked(_SCOPE, "scope.out")),
    Vector("s07-host-at-evil", 3, "ホスト@別ホスト", f"https://{SVC_HOST}@evil.example.invalid/", _blocked(_SCOPE, "url.userinfo")),
    Vector("s07-self-api-denied", 3, "自サービスの /api/（自己再帰の防止）", f"https://{SVC_HOST}/api/run", _blocked(_SCOPE, "scope.out")),
    # ---- tier 3: その他の URL の書き方
    Vector("url-backslash", 3, "バックスラッシュ", f"https://{SVC_HOST}\\@evil.example.invalid/", _blocked(_SCOPE, "url.backslash")),
    Vector("url-fullwidth-ip", 3, "全角数字の IP（127.0.0.1）", "https://１２７．０．０．１/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-short-ip", 3, "短縮形の IP（127.1）", "https://127.1/", _blocked(_SCOPE, "url.host_ip_literal")),
    Vector("url-localhost", 3, "localhost", "https://localhost/", _blocked(_SCOPE, "url.host_denied")),
    Vector("url-idna-one-dot-leader", 3, "U+2024（ONE DOT LEADER）で点を作る。IDNA 2003 は範囲内のホストへ畳むが、ブラウザは拒否する", f"https://{SVC_HOST.replace('.', chr(0x2024))}/fx/a", _blocked(_SCOPE, "url.host_idna")),
    Vector("url-idna-sharp-s", 3, "ß（IDNA 2003 は ss、ブラウザは別のホスト）", "https://stra\u00dfe.example.invalid/", _blocked(_SCOPE, "url.host_idna")),
    Vector("url-dot-local", 3, "*.local", "https://printer.local/", _blocked(_SCOPE, "url.host_denied")),
    Vector("url-dotless-host", 3, "ドット無しホスト", "https://intranet/", _blocked(_SCOPE, "url.host_dotless")),
    Vector("url-percent-host", 3, "パーセントエンコードされたホスト", "https://svc%2eexample.invalid/fx/a", _blocked(_SCOPE, "url.host_percent")),
    Vector("url-empty-port", 3, "空のポート", f"https://{SVC_HOST}:/fx/a", _blocked(_SCOPE, "url.port")),
    Vector("url-http-scheme", 3, "http（暗号化なし）", f"http://{SVC_HOST}/fx/a", _blocked(_SCOPE, "url.scheme")),
    Vector("url-path-semicolon", 3, "パスの ;（パスパラメータ）", f"https://{SVC_HOST}/fx;x=1/a", _blocked(_SCOPE, "url.path_semicolon")),
    Vector("url-path-double-slash", 3, "パスの //", f"https://{SVC_HOST}/fx//a", _blocked(_SCOPE, "url.path_double_slash")),
    Vector("url-path-nul", 3, "パスの %00", f"https://{SVC_HOST}/fx/a%00.html", _blocked(_SCOPE, "url.path_escape")),
    Vector("url-path-overlong-utf8", 3, "過長 UTF-8 のスラッシュ（%c0%af）", f"https://{SVC_HOST}/fx/%c0%afa", _blocked(_SCOPE, "url.path_escape")),
    Vector("url-too-long", 3, "2048字超の URL", f"https://{SVC_HOST}/fx/" + "a" * 2100, _blocked(_SCOPE, "url.too_long")),
    Vector("url-with-newline", 3, "改行を含む URL", f"https://{SVC_HOST}/fx/a\nHost: evil.example.invalid", _blocked(_SCOPE, "url.bad_char")),
    # ---- tier 3: DNS の応答（IP の種類）
    Vector("dns-rebinding-private-first", 3, "最初の応答が私有 IP（2回目は公開でも拒否）", _PAGE_URL, _blocked(_IP, "ip.private"), dns={SVC_HOST: ((PRIVATE_IP,), (PUBLIC_IP,))}, never_connect=(PRIVATE_IP, PUBLIC_IP)),
    Vector("dns-loopback", 3, "ループバックへ解決", _PAGE_URL, _blocked(_IP, "ip.loopback"), dns={SVC_HOST: (("127.0.0.1",),)}, never_connect=("127.0.0.1",)),
    Vector("dns-cgnat", 3, "CGNAT（100.64/10）へ解決", _PAGE_URL, _blocked(_IP, "ip.cgnat"), dns={SVC_HOST: ((_CGNAT_IP,),)}, never_connect=(_CGNAT_IP,)),
    Vector("dns-unspecified", 3, "0.0.0.0 へ解決", _PAGE_URL, _blocked(_IP, "ip.unspecified"), dns={SVC_HOST: (("0.0.0.0",),)}, never_connect=("0.0.0.0",)),
    Vector("dns-multicast", 3, "マルチキャストへ解決（is_global が真になる値）", _PAGE_URL, _blocked(_IP, "ip.multicast"), dns={SVC_HOST: (("224.0.0.1",),)}, never_connect=("224.0.0.1",)),
    Vector("dns-ipv6-ula", 3, "IPv6 の ULA（fc00::/7）", _PAGE_URL, _blocked(_IP, "ip.private"), dns={SVC_HOST: (("fd12:3456::1",),)}, never_connect=("fd12:3456::1",)),
    Vector("dns-ipv6-loopback", 3, "::1 へ解決", _PAGE_URL, _blocked(_IP, "ip.loopback"), dns={SVC_HOST: (("::1",),)}, never_connect=("::1",)),
    Vector("dns-nat64-embedded-loopback", 3, "NAT64 に入れた 127.0.0.1（is_global が真になる値）", _PAGE_URL, _blocked(_IP, "nat64>ip.loopback"), dns={SVC_HOST: (("64:ff9b::7f00:1",),)}, never_connect=("64:ff9b::7f00:1",)),
    Vector("dns-ipv4-compatible", 3, "IPv4 互換 ::8.8.8.8（is_global が真になる値）", _PAGE_URL, _blocked(_IP, "ip.transition"), dns={SVC_HOST: (("::808:808",),)}, never_connect=("::808:808",)),
    Vector("dns-teredo", 3, "Teredo", _PAGE_URL, _blocked(_IP, "ip.transition"), dns={SVC_HOST: (("2001:0:4136:e378:8000:63bf:3fff:fdd2",),)}, never_connect=("2001:0:4136:e378:8000:63bf:3fff:fdd2",)),
    Vector("dns-6to4", 3, "6to4（中身は公開 IP でも拒否）", _PAGE_URL, _blocked(_IP, "ip.transition"), dns={SVC_HOST: (("2002:808:808::1",),)}, never_connect=("2002:808:808::1",)),
    Vector("dns-zone-id", 3, "ゾーン ID 付きのリンクローカル", _PAGE_URL, _blocked(_IP, "ip.scope_id"), dns={SVC_HOST: (("fe80::1%eth0",),)}, never_connect=("fe80::1%eth0",)),
    Vector("dns-azure-wireserver", 3, "Azure の WireServer（公開アドレス空間にあるのに内部専用。is_global が真になる値）", _PAGE_URL, _blocked(_IP, "ip.metadata"), dns={SVC_HOST: (("168.63.129.16",),)}, never_connect=("168.63.129.16",)),
    Vector("dns-google-private-access-vip", 3, "Google の Private Google Access の仮想 IP（199.36.153.8）", _PAGE_URL, _blocked(_IP, "ip.metadata"), dns={SVC_HOST: (("199.36.153.8",),)}, never_connect=("199.36.153.8",)),
    # ---- tier 3: 転送
    Vector(
        "redirect-to-http", 3, "スコープ内 → 302 → http", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:url.scheme", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", f"http://{SVC_HOST}/fx/b"),))},
    ),
    Vector(
        "redirect-to-port-8443", 3, "スコープ内 → 302 → 8443", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:url.port", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", f"https://{SVC_HOST}:8443/fx/b"),))},
    ),
    Vector(
        "redirect-to-out-of-scope", 3, "スコープ内 → 302 → スコープ外ホスト", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:scope.out", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "https://other.example.invalid/x"),))},
    ),
    Vector(
        "redirect-to-api-path", 3, "スコープ内 → 302 → 同じホストのスコープ外パス（/api/）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:scope.out", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/api/run"),))},
    ),
    Vector(
        "redirect-bad-location", 3, "Location が UTF-8 でない", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:redirect.bad_location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/fx/ÿþ"),))},  # latin-1 で送る → UTF-8 としては不正
    ),
    Vector(
        "redirect-location-with-tab", 3, "Location にタブ（URL パーサが黙って除去する文字。除去後は範囲内に見える）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:redirect.bad_location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/fx/\tb"),))},
    ),
    Vector(
        "redirect-location-with-backslash", 3, "Location にバックスラッシュ（ブラウザは / と読む）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:redirect.bad_location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/fx\\..\\api/run"),))},
    ),
    Vector(
        "redirect-triple-slash-authority", 3, "Location が ///host（ブラウザは別ホストへ行く。urljoin は同じホストのパスと読む）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:redirect.bad_location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "///evil.example.invalid/x"),))},
    ),
    Vector(
        "redirect-https-triple-slash", 3, "Location が https:///host", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=302, hop_policy=_SCOPE, note="hop1:redirect.bad_location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "https:///evil.example.invalid/x"),))},
    ),
    Vector(
        "redirect-loop", 3, "転送の連鎖が4回を超える", f"https://{SVC_HOST}/fx/r0",
        Expect(outcome=FetchOutcome.TOO_MANY_REDIRECTS, status=302, limit_hit=FetchLimit.REDIRECTS),
        replies={f"{SVC_HOST}/fx/r{i}": Reply(status=302, headers=(("Location", f"/fx/r{i + 1}"),)) for i in range(0, 6)},
    ),
    # ---- tier 3: 本文・種別
    Vector(
        "body-slow-first-byte", 3, "応答が来ない（読み取りの期限）", _PAGE_URL,
        Expect(outcome=FetchOutcome.TIMEOUT, limit_hit=FetchLimit.READ_TIMEOUT),
        replies={_PAGE_KEY: Reply(body=b"<html>", first_byte_delay_s=5.0)},
    ),
    Vector(
        "body-endless-empty-gzip-blocks", 3, "展開後は0バイトのまま生の受信だけ続く gzip", _PAGE_URL,
        Expect(outcome=FetchOutcome.TOO_LARGE, status=200, limit_hit=FetchLimit.CONTENT_LENGTH, body_max=0),
        replies={
            _PAGE_KEY: Reply(
                headers=(*_HTML, ("Content-Encoding", "gzip")),
                prefix=bytes.fromhex("1f8b0800000000000003"),
                infinite=b"\x00\x00\x00\xff\xff" * 4096,
            )
        },
        limits_kw={"max_content_length": 256 * 1024},
    ),
    Vector(
        "encoding-nested", 3, "Content-Encoding の多重指定", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, body_max=0),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "gzip, gzip")), body=b"x")},
    ),
    Vector(
        "encoding-brotli", 3, "要求していない br", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, body_max=0),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "br")), body=b"x")},
    ),
    Vector(
        "type-missing", 3, "Content-Type が無い本文", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, body_max=0),
        replies={_PAGE_KEY: Reply(headers=(), body=b"<html>x")},
    ),
    Vector(
        "type-pdf", 3, "PDF（規約PDFは対象外）", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, body_max=0),
        replies={_PAGE_KEY: Reply(headers=(("Content-Type", "application/pdf"),), body=b"%PDF-1.7")},
    ),
    # ---- tier 3: 敵対レビュー（ssrf）で足した分。同名ヘッダの重複行・本文に数えられない受信
    Vector(
        "hdr-encoding-nested-over-two-lines", 3, "Content-Encoding: gzip を2行（1行の「gzip, gzip」と同じ＝入れ子として拒否）", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, note="encoding.multiple", body_max=0),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")), body=b"x")},
    ),
    Vector(
        "hdr-content-type-conflict", 3, "Content-Type が2行で食い違う（先頭は許可された HTML）", _PAGE_URL,
        Expect(outcome=FetchOutcome.UNSUPPORTED_TYPE, status=200, note="type.conflict", body_max=0),
        replies={_PAGE_KEY: Reply(headers=(("Content-Type", "text/html"), ("Content-Type", "application/x-msdownload")), body=b"<html>x</html>")},
    ),
    Vector(
        "hdr-location-conflict", 3, "Location が2行で食い違う（先頭だけを追わない）", _PAGE_URL,
        Expect(outcome=FetchOutcome.NETWORK_ERROR, status=302, note="header.conflict:location", connects=(PUBLIC_IP,), resolver_calls={SVC_HOST: 1}),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/fx/b"), ("Location", "https://svc2.example.invalid/x")))},
    ),
    Vector(
        "flood-one-byte-chunks", 3, "1バイトずつの chunked（本文の上限に届く前に CPU を使わせる）", _PAGE_URL,
        Expect(outcome=FetchOutcome.NETWORK_ERROR, note="net.fragmented_stream", body_max=0),
        replies={_PAGE_KEY: Reply(headers=_HTML, chunked=True, chunk_size=1, body=b"a" * 40_000)},
    ),
    Vector(
        "flood-informational-1xx", 3, "100 Continue の洪水（応答の先頭が終わらない）", _PAGE_URL,
        Expect(outcome=FetchOutcome.NETWORK_ERROR, note="net.head_flood", body_max=0),
        replies={_PAGE_KEY: Reply(headers=_HTML, informational=20_000, body=b"<html>x</html>")},
    ),
    Vector(
        "flood-chunk-extension", 3, "塊ごとに 60KB の chunk-extension（本文は小さいまま受信量だけ膨らむ）", _PAGE_URL,
        Expect(outcome=FetchOutcome.TOO_LARGE, status=200, limit_hit=FetchLimit.CONTENT_LENGTH, note="size.wire", body_max=0),
        replies={_PAGE_KEY: Reply(headers=_HTML, chunked=True, chunk_size=100, chunk_ext=60_000, body=b"a" * 12_000)},
    ),
)

ALL_VECTORS: tuple[Vector, ...] = _ALL
GATE2_VECTORS: tuple[Vector, ...] = tuple(v for v in _ALL if v.tier == 2)

# ---- 陽性対照: 通るべき書き方（拒否の試験が「何も通らない環境」で緑になっていないことを示す）
POSITIVE_CONTROLS: tuple[Vector, ...] = (
    Vector("ok-plain", 0, "ふつうの取得", _PAGE_URL, Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)), replies={_PAGE_KEY: _OK_PAGE}),
    Vector("ok-uppercase-host-trailing-dot", 0, "ホストの大文字・末尾ドット・明示の :443・fragment", f"https://{SVC_HOST.upper()}.:443/fx/a#frag", Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)), replies={_PAGE_KEY: _OK_PAGE}),
    Vector("ok-dot-segments-inside-scope", 0, "スコープ内に収まる ..（正規化した URL をそのまま接続に使う）", f"https://{SVC_HOST}/fx/x/../a", Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)), replies={_PAGE_KEY: _OK_PAGE}),
    Vector("ok-exact-lp", 0, "LP は正確な URL だけ（クエリは付けてよい）", f"https://{LP_HOST}/event?lang=ja", Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)), replies={f"{LP_HOST}/event?lang=ja": _OK_PAGE}),
    Vector(
        "ok-relative-redirect-in-scope", 0, "スコープ内への相対転送は追跡する", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP, PUBLIC_IP)),
        replies={_PAGE_KEY: Reply(status=302, headers=(("Location", "/fx/b"),)), f"{SVC_HOST}/fx/b": _OK_PAGE},
    ),
    Vector(
        "ok-encoding-identity-then-gzip-lines", 0, "Content-Encoding が identity と gzip の2行（RFC どおり gzip として展開）", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "identity"), ("Content-Encoding", "gzip")), body=b"<html>" + b"x" * 500, gzip=True)},
    ),
    Vector(
        "ok-gzip", 0, "ふつうの gzip", _PAGE_URL,
        Expect(outcome=FetchOutcome.OK, status=200, connects=(PUBLIC_IP,)),
        replies={_PAGE_KEY: Reply(headers=(*_HTML, ("Content-Encoding", "gzip")), body=b"<html>" + b"x" * 5000, gzip=True)},
    ),
)
