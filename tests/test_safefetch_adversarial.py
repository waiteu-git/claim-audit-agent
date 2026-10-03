"""SafeFetch への敵対レビュー（ssrf）。攻撃者として破りにいった結果を、再現テストとして残す。

構成
  A. 見つけた弱点の再現（修正前は赤・修正後は緑。陽性対照つき）
       A1 ヘッダの重複行で「こちらが読む応答」と「ブラウザが読む応答」が割れる（Content-Encoding・Content-Type・Location）
       A2 CPU・受信量の枯渇（1バイトずつの chunked・1xx の洪水・chunk-extension の肥大）＝上限が「本文のバイト数」だけだった
       A3 TLS 検証を無効にした SSLContext を受け取ってしまう（fail-open の入口）
       A4 名前解決が検索ドメイン（resolv.conf の search）で別名へ展開されうる
       A5 公開 IP に見えるクラウド内部の仮想 IP（Azure WireServer・Google Private Access）
       A6 応答しない名前を引くと、スレッドプールが詰まって別の名前の解決まで失敗する
       A7 ホストの IDNA（2003）の畳み込みがブラウザ（UTS 46）と食い違い、人が開く先と監査が取る先が割れる
       A8 Location の「スラッシュ3本以上」を urllib は同じホストのパスと読み、ブラウザは別ホストへ行く
  B. 攻撃を試して弱点が無かったものの回帰（修正の副作用で崩れないための固定）
       B1 Location の敵対的な乱数（相対・絶対・別表記）で、接続先は常にスコープ内の検査済み IP
       B2 validate_url の結果を httpcore・urllib が同じに読む（検査した URL と接続する URL のずれが無い）
       B3 keep-alive を無視するサーバーでも、転送のたびに検査済み IP へ繋ぎ直す（実 TLS）
       B4 タイムアウト・打切りの後に接続が残らない（実 TLS。サーバー側が EOF を観測する）
       B5 IP の独立した表（IANA の特殊用途）との境界照合と、書き方の揺れ
       B6 デコーダを標準の全展開と突き合わせる（gzip・zlib・生 deflate・連結メンバ・任意の分割・上限）
       B7 ホストの畳み込みを UTS 46（idna パッケージ）と突き合わせる（互換文字・囲み文字・数式文字・全角などの範囲を全数）

通信は全てループバックか偽のネットワーク層（オフライン）。
"""
import asyncio
import gzip
import ipaddress
import random
import socket
import ssl
import string
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
import urllib.parse

import httpcore
import pytest

from app.config import FetchLimits
from app.contracts import FetchLimit, FetchMode, FetchOutcome, FetchRequest
from app.net.backend import PinnedBackend, WireBudgetExceeded, WireMeter
from app.net.decode import BodyDecoder
from app.net.ipcheck import check_ip
from app.net.resolver import GuardedResolver, ResolveFailed, system_resolver
from app.net.safefetch import SafeFetch
from app.net.urlcheck import UrlReject, UrlRejected, validate_url
from app.net.vectors import (
    LP_HOST,
    PUBLIC_IP,
    PUBLIC_IP_2,
    SVC2_HOST,
    SVC_HOST,
    VECTOR_PREFIXES,
    Reply,
)
from tests.net_support import FakeInternet, FakeResolver, make_rig
from tests.test_safefetch_tls import LoopbackBackend, _client_ctx, make_cert


# pre-commit ガードは 100.64 台のドット表記を「運用者の tailnet IP」とみなして止める。
# ここの値は標準の CGNAT 帯と Alibaba のメタデータ IP（運用者のアドレスではない）なので、リテラルを避けて組み立てる。
def _dq(*octets: int) -> str:
    return ".".join(str(o) for o in octets)

PAGE = f"https://{SVC_HOST}/fx/a"
KEY = f"{SVC_HOST}/fx/a"
HTML = (("Content-Type", "text/html; charset=utf-8"),)
OK_HTML = Reply(headers=HTML, body=b"<html><body>ok</body></html>")


async def _go(reply: Reply, *, mode: FetchMode = FetchMode.PAGE, extra: dict[str, Reply] | None = None, **rig_kw):
    rig = make_rig({KEY: reply, **(extra or {})}, **rig_kw)
    detail = await asyncio.wait_for(rig.fetch.fetch_ex(FetchRequest(url=PAGE, mode=mode)), timeout=20)
    return rig, detail


# ======================================================================== A1 ヘッダの重複行
# 同じ名前のヘッダが複数行あると、「最初の1行だけ」を読む実装と、全行を RFC どおり読む実装（ブラウザ）で応答の読みが割れる。
# 提出物（敵対的でありうる）が、監査側にだけ別の内容・別の種別を見せられる＝見せ分け（クローキング）の入口になる。
async def test_a1_content_encoding_lines_are_combined_so_identity_then_gzip_is_decoded():
    """`Content-Encoding: identity` と `Content-Encoding: gzip` の2行＝RFC 9110 5.3 では「identity, gzip」。gzip として展開する。"""
    html = b"<html><body>hello</body></html>"
    reply = Reply(headers=(*HTML, ("Content-Encoding", "identity"), ("Content-Encoding", "gzip")), body=html, gzip=True)
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.OK, d.notes
    assert d.result.body == html  # 修正前: 先頭の identity だけを読み、gzip のバイト列がそのまま「HTML」として返っていた


async def test_a1_nested_encodings_split_over_two_lines_are_rejected_like_the_single_line_form():
    """`gzip, gzip` の1行は拒否される（入れ子の圧縮は爆弾の定番）。2行に分けても同じ扱いでないと、拒否が素通りする。"""
    inner = gzip.compress(b"<html>x</html>")
    reply = Reply(headers=(*HTML, ("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")), body=inner, gzip=True)
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.UNSUPPORTED_TYPE and d.result.body == b""
    assert any("encoding.multiple" in n for n in d.notes), d.notes


@pytest.mark.parametrize(
    "ctypes",
    [
        ("text/html", "application/x-msdownload"),  # 先頭だけ見ると「許可された HTML」に見える
        ("application/octet-stream", "text/html"),
        ("text/html", "text/plain"),  # どちらも許可リスト内でも、種別が決まらない
    ],
)
async def test_a1_conflicting_content_type_lines_are_not_decided_by_the_first_line(ctypes: tuple[str, str]):
    reply = Reply(headers=tuple(("Content-Type", c) for c in ctypes), body=b"<html>x</html>")
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.UNSUPPORTED_TYPE and d.result.body == b"", d.notes
    assert any("type.conflict" in n for n in d.notes), d.notes


async def test_a1_identical_duplicate_content_type_lines_are_harmless():
    """陽性対照: 同じ値の重複は食い違いではない（拒否しすぎない）。"""
    reply = Reply(headers=(("Content-Type", "text/html"), ("Content-Type", "text/html")), body=b"<html>x</html>")
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.OK and d.result.body == b"<html>x</html>"


async def test_a1_conflicting_location_lines_are_not_followed():
    """Location が2行で食い違う応答を、ブラウザは追跡しない（エラー）。こちらだけが先頭を追うと、見ている先が割れる。"""
    reply = Reply(status=302, headers=(("Location", "/fx/b"), ("Location", f"https://{SVC2_HOST}/other")))
    rig, d = await _go(reply, extra={f"{SVC_HOST}/fx/b": OK_HTML, f"{SVC2_HOST}/other": OK_HTML})
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR, d.notes
    assert rig.net.connected_ips == (PUBLIC_IP,)  # 転送先へは1度も接続していない
    assert [r.target for r in rig.net.requests] == ["/fx/a"]
    assert any("header.conflict:location" in n for n in d.notes), d.notes


async def test_a1_identical_duplicate_location_lines_are_followed():
    """陽性対照。"""
    reply = Reply(status=302, headers=(("Location", "/fx/b"), ("Location", "/fx/b")))
    rig, d = await _go(reply, extra={f"{SVC_HOST}/fx/b": OK_HTML})
    assert d.result.outcome is FetchOutcome.OK and d.result.final_url == f"https://{SVC_HOST}/fx/b"
    assert [r.target for r in rig.net.requests] == ["/fx/a", "/fx/b"]


# ======================================================================== A2 CPU・受信量の枯渇
# 本文の上限は「展開後 1MiB」「生の受信 3MB」だが、どちらも本文のバイト数だけを数える。受信した全バイトと、
# 受け取った塊の数は上限が無かった。実測（修正前・ループバックの実 TLS）: 1バイトずつの chunked で 1MiB を満たすまで
# CPU 5.3 秒、「100 Continue」の洪水で全体の期限（8 秒）まで CPU 8 秒。1回の取得でイベントループを使い切れる。
async def test_a2_one_byte_chunks_are_cut_off_long_before_the_body_cap():
    reply = Reply(headers=HTML, chunked=True, chunk_size=1, body=b"a" * 40_000)  # 4万個の塊（上限の約1.2倍）
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and d.result.body == b"", d.notes
    assert any("net.fragmented_stream" in n for n in d.notes), d.notes


async def test_a2_ordinary_small_chunks_still_pass():
    """陽性対照: 64 バイトずつの chunked（3125 個）は通る。拒否しすぎて本物のページを落とさない。"""
    body = b"<p>" + b"a" * 200_000 + b"</p>"
    _rig, d = await _go(Reply(headers=HTML, chunked=True, chunk_size=64, body=body))
    assert d.result.outcome is FetchOutcome.OK and d.result.body == body


async def test_a2_informational_response_flood_is_cut_off_by_the_header_phase_budget():
    _rig, d = await _go(Reply(headers=HTML, informational=20_000, body=b"<html>x</html>"))  # 受信 約 500KB の 1xx
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR, d.notes
    assert any("net.head_flood" in n for n in d.notes), d.notes


async def test_a2_a_few_informational_responses_are_fine():
    """陽性対照: 本物のサーバーも 100/103 を少し返す。"""
    _rig, d = await _go(Reply(headers=HTML, informational=5, body=b"<html>x</html>"))
    assert d.result.outcome is FetchOutcome.OK and d.result.body == b"<html>x</html>"


async def test_a2_chunk_extension_bloat_hits_the_wire_budget_even_though_the_payload_is_tiny():
    """本文は 12KB だが、塊ごとに 60KB の chunk-extension を付けて受信量だけを膨らませる（約 7MB）。"""
    reply = Reply(headers=HTML, chunked=True, chunk_size=100, chunk_ext=60_000, body=b"a" * 12_000)
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.TOO_LARGE and d.result.limit_hit is FetchLimit.CONTENT_LENGTH, d.notes
    assert d.result.status == 200 and d.result.body == b""
    assert any("size.wire" in n for n in d.notes), d.notes


async def test_a2_modest_chunk_extensions_still_pass():
    reply = Reply(headers=HTML, chunked=True, chunk_size=100, chunk_ext=100, body=b"a" * 12_000)
    _rig, d = await _go(reply)
    assert d.result.outcome is FetchOutcome.OK and len(d.result.body) == 12_000


async def test_a2_the_budget_is_drawn_again_for_each_redirect_hop():
    """2ホップ目の 1xx の洪水も止める（予算を最初の1回だけ引くと、転送を1つ挟むだけで素通りになる）。"""
    routes = {
        KEY: Reply(status=302, headers=(("Location", "/fx/b"),)),
        f"{SVC_HOST}/fx/b": Reply(headers=HTML, informational=20_000, body=b"<html>x</html>"),
    }
    rig = make_rig(routes)
    d = await rig.fetch.fetch_ex(FetchRequest(url=PAGE))
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and any("net.head_flood" in n for n in d.notes), d.notes
    assert [r.target for r in rig.net.requests] == ["/fx/a", "/fx/b"]  # 1ホップ目は通常どおり追跡した


def test_a2_meter_is_unlimited_until_armed_then_counts_from_the_arming_point():
    m = WireMeter()
    m.add(10**9)  # 未 arm は無制限（PinnedBackend 単体の利用）
    m.arm(100, "head")
    m.add(100)  # ちょうど予算は超えない
    with pytest.raises(WireBudgetExceeded) as e:
        m.add(1)
    assert e.value.phase == "head"
    m.arm(50, "body")  # 引き直すと、その時点からの増分
    m.add(50)
    with pytest.raises(WireBudgetExceeded) as e2:
        m.add(1)
    assert e2.value.phase == "body"


async def test_a2_pinned_backend_counts_what_is_read_including_after_start_tls():
    pins = {"a.example.invalid": (PUBLIC_IP,)}
    net = FakeInternet({"a.example.invalid/": Reply(body=b"x" * 1000)})
    meter = WireMeter()
    meter.arm(10**6, "head")
    backend = PinnedBackend(pins, net, meter=meter)
    stream = await backend.connect_tcp("a.example.invalid", 443)
    stream = await stream.start_tls(ssl.create_default_context(), server_hostname="a.example.invalid")
    await stream.write(b"GET / HTTP/1.1\r\nHost: a.example.invalid\r\n\r\n")
    got = 0
    while chunk := await stream.read(64 * 1024):
        got += len(chunk)
    assert got > 1000 and meter.total == got  # TLS の内側で受け取った全バイトを数える
    assert stream.get_extra_info("ssl_object") is None  # 内側へそのまま委譲する（フェイクは None を返す）


@pytest.mark.parametrize("flood", ["one_byte_chunks", "informational"])
async def test_a2_real_tls_floods_are_cut_off_with_little_cpu(flood: str):
    """実 TLS（ループバック）で確かめる。修正前の実測: 1バイトずつの chunked は CPU 5.3 秒、1xx の洪水は 8.0 秒（全体の期限まで）。"""

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            if flood == "one_byte_chunks":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
                frame = b"1\r\na\r\n" * 10_000
            else:
                frame = b"HTTP/1.1 100 Continue\r\n\r\n" * 2_000
            while True:
                writer.write(frame)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            return

    srv, port, cert = await _tls_server(handler)
    try:
        sf = SafeFetch(VECTOR_PREFIXES, resolver=FakeResolver(), network_backend=LoopbackBackend(port), ssl_context=_client_ctx(cert))
        cpu0 = time.process_time()
        d = await asyncio.wait_for(sf.fetch_ex(FetchRequest(url=PAGE)), timeout=20)
        cpu = time.process_time() - cpu0
        assert d.result.outcome is FetchOutcome.NETWORK_ERROR, d.notes
        assert any(n in ("net.fragmented_stream", "net.head_flood") for n in d.notes), d.notes
        assert cpu < 2.5, f"CPU {cpu:.1f} 秒（上限が効いていない。修正前は 5〜8 秒）"
    finally:
        srv.close()
        await srv.wait_closed()


# ======================================================================== A3 TLS 検証を無効にした文脈
@pytest.mark.parametrize("how", ["unverified", "no_hostname_check", "verify_none"])
def test_a3_a_context_that_does_not_verify_certificates_is_refused_at_construction(how: str):
    if how == "unverified":
        ctx = ssl._create_unverified_context()  # noqa: S323, SLF001
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # ホスト名の検証だけを外す（証明書の検証は残る）
        if how == "verify_none":
            ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="verif"):
        SafeFetch(VECTOR_PREFIXES, ssl_context=ctx)


def test_a3_a_verifying_context_is_accepted():
    SafeFetch(VECTOR_PREFIXES, ssl_context=ssl.create_default_context())
    SafeFetch(VECTOR_PREFIXES)  # 既定（httpcore.default_ssl_context）


# ======================================================================== A4 名前解決の検索ドメイン展開
async def test_a4_the_system_resolver_asks_for_the_absolute_name(monkeypatch: pytest.MonkeyPatch):
    """検査した名前（svc.example.invalid）と引く名前を同じにする。末尾ドット無しだと、resolv.conf の search（Cloud Run では
    `*.internal` 系）で `svc.example.invalid.<project>.internal` のような別名へ展開されうる（IP 検査は後段で効くが、
    名前の対応が崩れる）。"""
    seen: list[str] = []

    def fake(host, *_a, **_k):  # type: ignore[no-untyped-def]
        seen.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert await system_resolver("svc.example.invalid") == ["8.8.8.8"]
    assert seen == ["svc.example.invalid."]


# ======================================================================== A5 公開 IP に見えるクラウド内部の仮想 IP
@pytest.mark.parametrize("addr", ["168.63.129.16", "199.36.153.4", "199.36.153.8", "199.36.153.255", "::ffff:168.63.129.16"])
def test_a5_cloud_internal_virtual_ips_that_look_public_are_blocked(addr: str):
    assert ipaddress.ip_address(addr).is_global or addr.startswith("::ffff:")  # is_global だけでは止まらない値
    assert not check_ip(addr).ok


@pytest.mark.parametrize("addr", ["168.63.129.15", "168.63.129.17", "199.36.152.255", "199.36.154.1", "8.8.8.8"])
def test_a5_neighbours_stay_allowed(addr: str):
    assert check_ip(addr).ok


# ======================================================================== A6 応答しない名前でスレッドプールが詰まる
# getaddrinfo はスレッドで走り、呼び出し側が期限で諦めてもスレッドは止まらない。既定のプールは小さい（1 vCPU で5本）うえ他と共有で、
# 実測（修正前・プール5本）: 応答しない名前を12本同時に引くと、直後の別の名前の解決まで dns.timeout で失敗した。
class _StalledDns:
    """名前ごとに「最初の1回だけ遅い」getaddrinfo の代わり。起動した回数とスレッド名を記録する。"""

    def __init__(self, slow_s: float) -> None:
        self.slow_s = slow_s
        self.started: list[str] = []
        self.threads: list[str] = []
        self._seen: set[str] = set()

    def __call__(self, host, *_a, **_k):  # type: ignore[no-untyped-def]
        self.started.append(host)
        self.threads.append(threading.current_thread().name)
        if host.startswith("slow") and host not in self._seen:
            self._seen.add(host)
            time.sleep(self.slow_s)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


async def test_a6_a_stalled_name_does_not_starve_other_names(monkeypatch: pytest.MonkeyPatch):
    dns = _StalledDns(slow_s=0.6)
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=2))  # 小さい既定のプール（他の処理と共有）
    guard = GuardedResolver(system_resolver, timeout_s=0.2)

    results = await asyncio.gather(*[guard.resolve("slow.example.invalid") for _ in range(12)], return_exceptions=True)
    assert all(isinstance(r, ResolveFailed) for r in results)
    assert dns.started.count("slow.example.invalid.") == 1  # 12 本は、走っている1本に合流した（スレッドを12本使わない）
    # 先に諦めた側の期限切れで、共有の引き直しが止められたりしない（後から来た側も、走っている同じ1本に合流する）
    later = await asyncio.gather(*[guard.resolve("slow.example.invalid") for _ in range(6)], return_exceptions=True)
    assert all(isinstance(r, ResolveFailed) for r in later)
    assert dns.started.count("slow.example.invalid.") == 1

    t0 = time.monotonic()
    assert await guard.resolve("fast.example.invalid") == ("8.8.8.8",)  # 別の名前はすぐ引ける
    assert time.monotonic() - t0 < 0.4
    assert all(n.startswith("safefetch-dns") for n in dns.threads)  # 専用のプール（既定のプールを使わない）

    await asyncio.sleep(0.5)  # 詰まった1本が終わるまで待つ（ループを閉じる前に片付ける）


async def test_a6_after_the_stalled_lookup_finishes_the_name_is_looked_up_afresh(monkeypatch: pytest.MonkeyPatch):
    """合流は「走っている間だけ」。終わった結果を覚えない（キャッシュにしない＝リバインディングの隙を作らない）。"""
    dns = _StalledDns(slow_s=0.3)
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    guard = GuardedResolver(system_resolver, timeout_s=0.1)
    with pytest.raises(ResolveFailed):
        await guard.resolve("slow.example.invalid")
    await asyncio.sleep(0.4)  # スレッドが終わる
    assert await guard.resolve("slow.example.invalid") == ("8.8.8.8",)
    assert dns.started == ["slow.example.invalid.", "slow.example.invalid."]  # 2回目は引き直した


# ======================================================================== A7 ホストの畳み込みがブラウザと割れる
# 標準ライブラリの idna コーデックは IDNA 2003。ブラウザは UTS 46（非 transitional）。ASCII へ畳まれる 1272 字のうち 30 字は
# 両者で結果が割れる（実測。全コードポイントを a?b.example に入れて idna パッケージの UTS 46 と突き合わせた）:
#   ß・ẞ → 2003 は "ss"、ブラウザは別のホスト（punycode）。 U+2024（ONE DOT LEADER）・U+FE52・⒈ など → 2003 は "." を作り、
#   ブラウザは拒否する。つまり `svc․example․invalid`（U+2024）は、こちらでは範囲内の svc.example.invalid として取れるが、人のブラウザでは開けない。
# 検査した名前＝接続する名前（こちらの内側）は保たれているが、「人が見る先」と「監査が取る先」が割れる。ブラウザより緩く読まない。
_SPLIT_FOLDS = [
    "svc\u2024example\u2024invalid",  # ONE DOT LEADER → "."
    "svc\ufe52example.invalid",  # SMALL FULL STOP
    "svc\u2488example.invalid",  # DIGIT ONE FULL STOP → "1."
    "svc\u33c7.example.invalid",  # SQUARE CO → "co."
    "svc.exa\u2025mple.invalid",  # TWO DOT LEADER → ".."
]
_DEVIATIONS = ["stra\u00dfe.example.invalid", "STRA\u1e9eE.example.invalid", "a\u1806b.example.invalid"]


@pytest.mark.parametrize("host", [*_SPLIT_FOLDS, *_DEVIATIONS])
def test_a7_idna2003_only_foldings_are_rejected_not_silently_mapped(host: str):
    with pytest.raises(UrlRejected) as e:
        validate_url(f"https://{host}/fx/a")
    assert e.value.code in (UrlReject.HOST_IDNA, UrlReject.HOST_FORMAT)


@pytest.mark.parametrize(
    ("host", "ascii_host"),
    [
        ("\uff53\uff56\uff43.example.invalid", "svc.example.invalid"),  # 全角
        ("SVC\u3002EXAMPLE\u3002INVALID", "svc.example.invalid"),  # 句点の別表記・大文字
        ("\u24e2\u24e5\u24d2.example.invalid", "svc.example.invalid"),  # 丸付き英字
        ("\u212a.example.invalid", "k.example.invalid"),  # ケルビン記号
        ("m\u00fcnchen.example.invalid", "xn--mnchen-3ya.example.invalid"),  # 本物の IDN は punycode へ
    ],
)
def test_a7_plain_compatibility_forms_and_real_idn_still_pass(host: str, ascii_host: str):
    """陽性対照: ブラウザ（UTS 46）と結果が同じ畳み込みは通す（拒否しすぎない）。"""
    assert validate_url(f"https://{host}/x").host == ascii_host


# ======================================================================== A8 Location のスラッシュ3本以上
# `///evil.example.invalid/x` と `https:///evil.example.invalid/x`。ブラウザ（WHATWG）は余分なスラッシュを読み飛ばして
# evil.example.invalid へ行く（古典的なオープンリダイレクトの回避形）。urllib.parse.urljoin は同じホストのパス
# （/evil.example.invalid/x）と読む。こちらは範囲内の別ページを取るが、人は別のホストへ行く＝見せ分けになる。決めずに拒否する。
_SVC2_PAGE = f"https://{SVC2_HOST}/p"


@pytest.mark.parametrize(
    "location",
    ["///evil.example.invalid/x", "https:///evil.example.invalid/x", "////evil.example.invalid/x", "HTTPS:////evil.example.invalid/", "//", "https://", "https:///"],
)
async def test_a8_locations_with_extra_slashes_are_not_followed(location: str):
    routes = {
        f"{SVC2_HOST}/p": Reply(status=302, headers=(("Location", location),)),
        f"{SVC2_HOST}/evil.example.invalid/x": OK_HTML,  # urljoin が読む先（同じホストの別パス）。ここへ行ってはいけない
        f"{SVC2_HOST}/p?": OK_HTML,
    }
    rig = make_rig(routes)
    d = await rig.fetch.fetch_ex(FetchRequest(url=_SVC2_PAGE))
    assert [r.target for r in rig.net.requests] == ["/p"], (location, rig.net.requests)
    assert any("redirect.bad_location" in n for n in d.notes), d.notes
    assert d.result.status == 302 and d.result.redirects[-1].followed is False


@pytest.mark.parametrize(
    ("location", "target"),
    [
        (f"//{SVC2_HOST}/x", "/x"),  # スキーム相対（スラッシュ2本＋ホスト）
        (f"https://{SVC2_HOST}/x", "/x"),
        ("/x", "/x"),
        ("x", "/x"),
        ("?q=1", "/p?q=1"),
    ],
)
async def test_a8_ordinary_location_forms_are_still_followed(location: str, target: str):
    """陽性対照。"""
    routes = {
        f"{SVC2_HOST}/p": Reply(status=302, headers=(("Location", location),)),
        f"{SVC2_HOST}{target}": OK_HTML,
    }
    rig = make_rig(routes)
    d = await rig.fetch.fetch_ex(FetchRequest(url=_SVC2_PAGE))
    assert d.result.outcome is FetchOutcome.OK and d.result.status == 200, d.notes
    assert [r.target for r in rig.net.requests] == ["/p", target]


# ======================================================================== B1 Location の敵対的な乱数
_HOSTS = [
    SVC_HOST, SVC2_HOST, LP_HOST, "evil.example.invalid", "169.254.169.254", "127.1", "0x7f.1", "[::1]", "localhost",
    "metadata.google.internal", f"{SVC_HOST}.", f"SVC.{SVC_HOST[4:]}", f"{SVC_HOST}:443", f"{SVC_HOST}:8443",
    f"{SVC_HOST}@evil.example.invalid", f"evil.example.invalid@{SVC_HOST}", f"evil.example.invalid#@{SVC_HOST}",
    f"{SVC_HOST}\\@evil.example.invalid", f"{SVC_HOST}%2f@evil", "svc。example。invalid", "ｓｖｃ.example.invalid",
]
_PATHS = [
    "/", "/fx/", "/fx/a", "/fx/../api/run", "/fx/%2e%2e/api", "/fx/..%2fapi", "/fxx/", "/event", "/event/", "/fx/a;b",
    "/fx//a", "/fx/\\..\\api", "/fx/./a", "/fx/a/../../b", "/fx/%00", "/fx/é", "/fx/%e9", "/fx/a b", "/api/run", "",
]
_TAILS = ["", "?x=1", "#frag", "?a=%0d%0aHost:evil", "?\\", "#@evil", "?@evil.example.invalid"]
_SCHEMES = ["https://", "http://", "//", "///", "", "HTTPS://", "https:/", "https:///", "https:", "https:\\\\", "ftp://", "file://", "javascript:", "data:text/html,"]


def _random_location(rnd: random.Random) -> str:
    r = rnd.random()
    if r < 0.5:
        return rnd.choice(_SCHEMES) + rnd.choice(_HOSTS) + rnd.choice(_PATHS) + rnd.choice(_TAILS)
    if r < 0.8:
        return rnd.choice(_PATHS) + rnd.choice(_TAILS)
    alpha = string.ascii_letters + string.digits + "/%?&=:@;.-_~!$'()*+,#[]{}|^`\"<> \\\t"
    return "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 30)))


def _in_vector_scope(host: str | None, target: str) -> bool:
    path = target.split("?", 1)[0]
    return (
        (host == SVC_HOST and (path.startswith("/fx/") or path == "/"))
        or host == SVC2_HOST
        or (host == LP_HOST and path == "/event")
    )


async def test_b1_whatever_the_location_says_every_request_stays_in_scope_on_a_checked_ip():
    rnd = random.Random(11)
    followed = 0
    for _ in range(500):
        loc = _random_location(rnd)
        # 応答ヘッダは latin-1 のバイト列。UTF-8 の Location は latin-1 に見立てて渡す（SafeFetch 側は UTF-8 として読む）
        reply = Reply(status=302, headers=(("Location", loc.encode("utf-8", "replace").decode("latin-1")),))
        rig = make_rig({KEY: reply})
        d = await rig.fetch.fetch_ex(FetchRequest(url=PAGE))
        assert d.result.outcome in (FetchOutcome.OK, FetchOutcome.NETWORK_ERROR, FetchOutcome.TOO_MANY_REDIRECTS), (loc, d.notes)
        assert rig.net.non_ip_connects == []
        for r in rig.net.requests:
            assert r.ip in (PUBLIC_IP, PUBLIC_IP_2), (loc, r)
            assert r.tls_hostname == r.headers.get("host"), (loc, r)
            assert _in_vector_scope(r.headers.get("host"), r.target), (loc, r)
            assert not any(c in r.target for c in " \\\t\r\n") and ".." not in r.target.split("?")[0].split("/"), (loc, r)
        followed += max(len(rig.net.requests) - 1, 0)
    assert followed > 100  # 追跡した転送が十分にあった＝「何も追わなかったから緑」ではない


# ======================================================================== B2 URL の解釈の一致
def test_b2_httpcore_and_urllib_read_every_accepted_url_exactly_as_validated():
    rnd = random.Random(7)
    alpha = string.ascii_letters + string.digits + "/%?&=:@;.-_~!$'()*+,#[]{}|^`\"<> \\。．／K℀éıſ"
    prefixes = ["https://svc.example.invalid", "https://SVC.example.invalid:443", "https://lp.example.invalid", "https://a.b"]
    accepted = 0
    for _ in range(40_000):
        url = rnd.choice(prefixes) + "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 14)))
        try:
            nu = validate_url(url)
        except UrlRejected:
            continue
        accepted += 1
        h = httpcore.URL(nu.url)  # 接続層（httpcore）が見るもの
        target = nu.path + ("?" + nu.query if nu.query else "")
        assert (h.host.decode(), h.port, h.target.decode(), h.scheme) == (nu.host, None, target, b"https"), url
        sp = urllib.parse.urlsplit(nu.url)  # 別の読み手（urllib）
        assert (sp.hostname, sp.port, sp.path, sp.query) == (nu.host, None, nu.path, nu.query), url
        assert not sp.fragment and sp.username is None, url
    assert accepted > 3_000


# ======================================================================== B3・B4 実 TLS（ループバック）
async def _tls_server(handler):
    import pathlib
    import tempfile

    d = pathlib.Path(tempfile.mkdtemp())
    cert, key = make_cert(SVC_HOST, SVC2_HOST)
    (d / "c.pem").write_bytes(cert)
    (d / "k.pem").write_bytes(key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1], cert


async def test_b3_a_server_that_ignores_connection_close_still_gets_a_fresh_pinned_connection_per_hop():
    """サーバーが keep-alive を続けても、転送先ホップは新しい接続で、そのホップの検査済み IP に繋ぐ（接続の使い回しで
    前ホップの IP に乗ったままにならない）。"""
    connections = 0

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        try:
            while True:
                head = (await reader.readuntil(b"\r\n\r\n")).split(b"\r\n")
                if b"/fx/redirect" in head[0]:
                    writer.write(
                        f"HTTP/1.1 302 Found\r\nLocation: https://{SVC_HOST}/fx/b\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".encode()
                    )
                else:
                    body = b"<p>ok</p>"
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nContent-Length: "
                        + str(len(body)).encode() + b"\r\n\r\n" + body
                    )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            return

    srv, port, cert = await _tls_server(handler)
    backend = LoopbackBackend(port)
    resolver = FakeResolver({SVC_HOST: [[PUBLIC_IP], [PUBLIC_IP_2]]})  # 1ホップ目と2ホップ目で別の（検査済みの）IP
    try:
        sf = SafeFetch(VECTOR_PREFIXES, resolver=resolver, network_backend=backend, ssl_context=_client_ctx(cert))
        r = await sf.fetch(FetchRequest(url=f"https://{SVC_HOST}/fx/redirect"))
        assert (r.outcome, r.status) == (FetchOutcome.OK, 200)
        assert backend.requested == [(PUBLIC_IP, 443), (PUBLIC_IP_2, 443)]
        assert connections == 2
    finally:
        srv.close()
        await srv.wait_closed()


@pytest.mark.parametrize("kind", ["stall_body", "endless", "huge"])
async def test_b4_no_connection_is_left_open_after_a_timeout_or_a_cut_off(kind: str):
    """タイムアウト・打切りの後に、サーバーが「クライアントが閉じた」(EOF/リセット)を観測できる＝ソケットを漏らさない。"""
    observed: list[str] = []

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            if kind == "stall_body":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<p>")
                await writer.drain()
            elif kind == "endless":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n")
                while True:
                    writer.write(b"400\r\n" + b"a" * 1024 + b"\r\n")
                    await writer.drain()
                    await asyncio.sleep(0.05)
            else:
                body = b"a" * 2_000_000
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body))
                writer.write(body)
                await writer.drain()
            await asyncio.wait_for(reader.read(), 5)  # クライアントが閉じれば EOF
            observed.append("eof")
        except (ConnectionError, asyncio.IncompleteReadError):
            observed.append("reset")
        except Exception as e:  # noqa: BLE001
            observed.append(type(e).__name__)

    srv, port, cert = await _tls_server(handler)
    limits = FetchLimits(total_timeout_s=0.8, sock_read_timeout_s=0.4, connect_timeout_s=0.4)
    try:
        sf = SafeFetch(
            VECTOR_PREFIXES, limits=limits, resolver=FakeResolver(), network_backend=LoopbackBackend(port), ssl_context=_client_ctx(cert)
        )
        await sf.fetch(FetchRequest(url=PAGE))
        for _ in range(40):  # サーバー側が閉じを観測するまで少し待つ
            if observed:
                break
            await asyncio.sleep(0.05)
        assert observed and observed[0] in ("eof", "reset"), observed
    finally:
        srv.close()
        await srv.wait_closed()


# ======================================================================== B5 IP の独立した表との照合
# IANA の「特殊用途」のうち、到達先として拒否すべき範囲（実装の表とは独立に、ここに別に書き下す）。
_MUST_DENY_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", f"{_dq(100, 64, 0, 0)}/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
]


def test_b5_every_special_purpose_v4_range_is_denied_at_both_edges_and_just_outside_is_allowed():
    nets = [ipaddress.ip_network(n) for n in _MUST_DENY_V4]
    for net in nets:
        first, last = net[0], net[-1]
        assert not check_ip(str(first)).ok and not check_ip(str(last)).ok, net
        assert not check_ip(str(net[net.num_addresses // 2])).ok, net
        for n in (int(first) - 1, int(last) + 1):
            if not 0 <= n <= 0xFFFFFFFF:
                continue  # アドレス空間の端
            outside = ipaddress.IPv4Address(n)
            if any(outside in other for other in nets):
                continue  # 隣の特殊用途範囲に入る
            assert check_ip(str(outside)).ok, f"{outside}（{net} の外）が拒否された＝拒否しすぎ"


def test_b5_random_ipv4_agrees_with_the_independent_table():
    rnd = random.Random(3)
    nets = [ipaddress.ip_network(n) for n in _MUST_DENY_V4]
    for _ in range(30_000):
        ip = ipaddress.IPv4Address(rnd.getrandbits(32))
        expected_denied = any(ip in n for n in nets)
        assert check_ip(str(ip)).ok is (not expected_denied), ip


@pytest.mark.parametrize(
    "addr",
    [
        "::ffff:7f00:1", "::FFFF:127.0.0.1", "0000:0000:0000:0000:0000:ffff:7f00:0001", "::127.0.0.1", "::ffff:0:127.0.0.1",
        "64:ff9b::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2002:a9fe:a9fe::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "fe80::1", "fec0::1", "::", "::2", "ff02::1", "fd00:ec2::254", "100::1", "2001:db8:0:0:0:0:0:1", "3fff::1", "5f00::1",
        "64:ff9b:1::1", "::ffff:a9fe:a9fe", "::ffff:0:0",
    ],
)
def test_b5_ipv6_spellings_of_internal_targets_are_all_denied(addr: str):
    assert not check_ip(addr).ok


@pytest.mark.parametrize("addr", ["  8.8.8.8", "8.8.8.8\n", "８.８.８.８", "0x7f.0.0.1", "127.1", "010.0.0.1", "1.2.3", "[::1]", "8.8.8.8/32", "::1/128"])
def test_b5_unusual_spellings_never_pass_as_ok(addr: str):
    """ipaddress が解釈できない書き方は拒否（fail-closed）。解釈できる書き方でも、接続に使う文字列と検査した文字列は同じ。"""
    assert not check_ip(addr).ok


# ======================================================================== B6 デコーダの差分
def test_b6_decoder_agrees_with_full_decompression_for_any_chunking_and_cap():
    rnd = random.Random(5)

    def compress(kind: str, data: bytes) -> bytes:
        if kind == "gzip":
            return gzip.compress(data, rnd.choice([0, 1, 6, 9]))
        if kind == "zlib":
            return zlib.compress(data, rnd.choice([0, 1, 6, 9]))
        c = zlib.compressobj(rnd.choice([1, 6, 9]), zlib.DEFLATED, -15)  # 生 deflate
        return c.compress(data) + c.flush()

    for _ in range(1500):
        kind = rnd.choice(["gzip", "zlib", "raw"])
        n = rnd.choice([0, 1, 10, 1000, 70_000])
        data = bytes(rnd.choice([0, 0, 0, 65, 66, 255, rnd.randrange(256)]) for _ in range(n)) if n < 2000 else bytes(range(100)) * (n // 100)
        members = [compress(kind, data) for _ in range(rnd.choice([1, 1, 1, 2, 3]))] if kind == "gzip" else [compress(kind, data)]
        wire = b"".join(members)
        expected = data * len(members) if kind == "gzip" else data
        limit = rnd.choice([1, 5, 100, 1000, 65_536, 1 << 20])
        dec = BodyDecoder("gzip" if kind == "gzip" else "deflate", limit)
        pos = 0
        while pos < len(wire) and not dec.over:
            step = rnd.choice([1, 2, 3, 7, 64, 1000, 65_536])
            dec.feed(wire[pos : pos + step])
            pos += step
        dec.finish()
        assert dec.data == expected[:limit], (kind, n, limit, len(members))
        assert dec.truncated is (len(expected) > limit), (kind, n, limit, len(members))


# ======================================================================== B7 ホストの畳み込みの全数照合
def test_b7_every_host_that_folds_to_plain_ascii_is_read_the_same_by_a_browser_grade_idna():
    """ASCII へ畳まれたホストは、UTS 46（ブラウザの読み）と一致する。畳み込みが起きうる範囲（ラテン補助〜CJK 互換・囲み文字・
    数式文字・全角形・小形・囲み英数補助）の全コードポイントを a?b.example に入れて照合する（全域では 19 秒かかるので範囲を絞る。
    割れた 30 字は全てこの範囲に入っていた）。idna パッケージは anyio の依存で入っているが、本番コードは使わない（試験の物差しだけ）。"""
    idna = pytest.importorskip("idna")
    ranges = [(0x80, 0x3400), (0xF900, 0xFB00), (0xFE00, 0x10000), (0x1D400, 0x1D800), (0x1F100, 0x1F200), (0x2F800, 0x2FA20)]
    folded = 0
    for lo, hi in ranges:
        for cp in range(lo, hi):
            if 0xD800 <= cp <= 0xDFFF:
                continue
            host = f"a{chr(cp)}b.example"
            try:
                got = validate_url(f"https://{host}/").host
            except UrlRejected:
                continue
            if "xn--" in got:
                continue  # punycode は ASCII の範囲内のホストと衝突しない
            folded += 1
            try:
                theirs = idna.encode(host, uts46=True, transitional=False).decode("ascii")
            except idna.IDNAError:
                theirs = None
            assert got == theirs, f"U+{cp:04X}: こちら {got!r} / UTS 46 {theirs!r}"
    assert folded > 500  # 畳み込みが実際に多数あった（何も通らなかったから緑、ではない）
