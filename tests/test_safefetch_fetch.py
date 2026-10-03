"""SafeFetch の取得の流れ（app/net/safefetch.py）。偽の名前解決・偽のネットワーク層で、完全オフライン。

ベクタ（test_safefetch_vectors.py）が「悪い入力が拒否される」を見るのに対し、ここは「普通の入力が契約どおりに返る」と
「失敗が例外にならず outcome で返る」を見る。FetchResult の不変条件は契約側（pydantic）が強制するので、
ここで結果が組み立てられること自体がその確認になる。
"""
import asyncio
import gzip
import zlib

import httpcore
import pytest

from app.config import FETCH_LIMITS, FetchLimits
from app.contracts import (
    ALLOWED_RESPONSE_HEADERS,
    ContentKind,
    FetchLimit,
    FetchMode,
    FetchOutcome,
    FetchPort,
    FetchRequest,
    PolicyId,
)
from app.net.safefetch import SafeFetch, classify_content_type
from app.net.vectors import (
    LP_HOST,
    PRIVATE_IP,
    PUBLIC_IP,
    PUBLIC_IP_2,
    SVC2_HOST,
    SVC_HOST,
    VECTOR_LIMITS_KW,
    VECTOR_PREFIXES,
    Reply,
)
from app.textsafe import is_safe_text
from tests.net_support import FAKE_SSL, FakeInternet, FakeResolver, make_rig

PAGE = f"https://{SVC_HOST}/fx/a"
KEY = f"{SVC_HOST}/fx/a"
SHORT = FetchLimits(**VECTOR_LIMITS_KW)
HTML = (("Content-Type", "text/html; charset=utf-8"),)


def req(url: str = PAGE, mode: FetchMode = FetchMode.PAGE) -> FetchRequest:
    return FetchRequest(url=url, mode=mode)


# ---------------------------------------------------------------- 基本
async def test_ok_response_carries_status_body_headers_and_kind():
    rig = make_rig({KEY: Reply(headers=(*HTML, ("X-Audit-App", "1")), body=b"<html>hello</html>")})
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.status, r.body, r.content_kind) == (FetchOutcome.OK, 200, b"<html>hello</html>", ContentKind.HTML)
    assert r.requested_url == PAGE and r.final_url == PAGE and r.redirects == () and r.truncated is False
    assert r.has_audit_app_header and r.headers["content-type"] == "text/html; charset=utf-8"
    assert r.body_sha256 and r.elapsed_ms >= 0


async def test_safefetch_satisfies_the_fetch_port_protocol():
    rig = make_rig()
    assert isinstance(rig.fetch, FetchPort)


async def test_request_is_get_only_with_fixed_headers_and_pinned_to_the_checked_ip():
    rig = make_rig({KEY: Reply(body=b"x")})
    await rig.fetch.fetch(req())
    (seen,) = rig.net.requests
    assert (seen.method, seen.target, seen.ip) == ("GET", "/fx/a", PUBLIC_IP)
    assert seen.headers["host"] == SVC_HOST and seen.tls_hostname == SVC_HOST  # Host と SNI は元のホスト名
    assert seen.headers["user-agent"] == FETCH_LIMITS.user_agent
    assert seen.headers["accept-encoding"] == "gzip, deflate" and seen.headers["connection"] == "close"
    forbidden = {"cookie", "authorization", "proxy-authorization", "referer", "origin", "x-forwarded-for", "forwarded"}
    assert forbidden & set(seen.headers) == set()
    assert rig.net.connects == [(PUBLIC_IP, 443)] and rig.net.non_ip_connects == []
    assert rig.resolver.calls == {SVC_HOST: 1}


async def test_query_string_is_sent_and_the_normalized_path_is_what_connects():
    rig = make_rig({f"{LP_HOST}/event?lang=ja&x=%2F": Reply(body=b"x"), f"{SVC_HOST}/fx/b": Reply(body=b"y")})
    assert (await rig.fetch.fetch(req(f"https://{LP_HOST}/event?lang=ja&x=%2F#top"))).status == 200
    r2 = await rig.fetch.fetch(req(f"https://{SVC_HOST}/fx/./c/../b"))
    assert r2.status == 200 and r2.final_url == f"https://{SVC_HOST}/fx/b"
    assert [s.target for s in rig.net.requests] == ["/event?lang=ja&x=%2F", "/fx/b"]
    assert rig.net.unrouted == []


async def test_ipv6_answers_are_connected_by_literal_and_ipv4_is_tried_first():
    rig = make_rig({KEY: Reply(body=b"x")}, dns={SVC_HOST: [["2606:4700:4700::1111", PUBLIC_IP]]})
    assert (await rig.fetch.fetch(req())).status == 200
    assert rig.net.connected_ips == (PUBLIC_IP,)
    rig6 = make_rig({KEY: Reply(body=b"x")}, dns={SVC_HOST: [["2606:4700:4700::1111"]]})
    assert (await rig6.fetch.fetch(req())).status == 200
    assert rig6.net.connected_ips == ("2606:4700:4700::1111",) and rig6.net.non_ip_connects == []


# ---------------------------------------------------------------- 応答ヘッダ
async def test_only_allow_listed_headers_survive_lowercased_and_sanitized():
    reply = Reply(
        headers=(
            ("Content-Type", "text/html"),
            ("Server", "demo"),
            ("Via", "1.1 a"),
            ("Via", "1.1 b"),
            ("Set-Cookie", "sid=secret"),
            ("X-Powered-By", "php"),
            ("Content-Security-Policy", "default-src 'none'"),
            ("Strict-Transport-Security", "max-age=1"),
            ("X-Audit-App", "1"),
            ("Cache-Control", "no-store"),
            ("Retry-After", "60"),
            ("Server-Timing", "x"),
        ),
        body=b"x",
    )
    r = await make_rig({KEY: reply}).fetch.fetch(req())
    assert set(r.headers) <= ALLOWED_RESPONSE_HEADERS and "set-cookie" not in r.headers and "x-powered-by" not in r.headers
    assert r.headers["via"] == "1.1 a, 1.1 b"  # 同名は連結
    assert r.headers["server"] == "demo" and r.headers["x-audit-app"] == "1" and r.headers["retry-after"] == "60"


async def test_header_values_are_cut_at_300_chars_and_unsafe_characters_are_removed():
    long_value = "v" * 500
    reply = Reply(headers=(("Content-Type", "text/html"), ("Server", long_value), ("Via", "a\u0085bé­ c")), body=b"x")
    r = await make_rig({KEY: reply}).fetch.fetch(req())
    # latin-1 の 0x85（NEL）は空白類・0xAD（ソフトハイフン）は Cf。契約の検証（安全文字のみ）を通る形で返る
    assert len(r.headers["server"]) == 300 and r.outcome is FetchOutcome.OK
    assert all(is_safe_text(v, allow_block_sep=False) for v in r.headers.values())
    assert "\u0085" not in r.headers["via"] and "­" not in r.headers["via"]


# ---------------------------------------------------------------- 種別
@pytest.mark.parametrize(
    ("ctype", "kind"),
    [
        ("text/html", ContentKind.HTML),
        ("text/html; charset=Shift_JIS", ContentKind.HTML),
        ("TEXT/HTML;charset=utf-8", ContentKind.HTML),
        ("application/xhtml+xml", ContentKind.XHTML),
        ("text/plain; charset=utf-8", ContentKind.PLAIN),
        ("text/markdown", ContentKind.MARKDOWN),
        ("text/x-markdown", ContentKind.MARKDOWN),
        ("application/json", ContentKind.JSON),
        ("application/ld+json", ContentKind.JSON),
        ("application/problem+json; charset=utf-8", ContentKind.JSON),
    ],
)
async def test_allowed_content_types_are_classified(ctype: str, kind: ContentKind):
    r = await make_rig({KEY: Reply(headers=(("Content-Type", ctype),), body=b"x")}).fetch.fetch(req())
    assert (r.outcome, r.content_kind, r.body) == (FetchOutcome.OK, kind, b"x")
    assert classify_content_type(ctype) is kind


@pytest.mark.parametrize(
    "ctype",
    ["image/png", "application/pdf", "application/octet-stream", "text/css", "application/javascript", "text/javascript",
     "application/xml", "text/xml", "video/mp4", "application/zip", "text/htmlx", "application/jsonx", "", "garbage"],
)
async def test_other_content_types_are_unsupported_and_return_no_body(ctype: str):
    r = await make_rig({KEY: Reply(headers=(("Content-Type", ctype),), body=b"payload")}).fetch.fetch(req())
    assert (r.outcome, r.status, r.body, r.content_kind) == (FetchOutcome.UNSUPPORTED_TYPE, 200, b"", ContentKind.UNSUPPORTED)


async def test_statuses_other_than_200_are_ok_outcomes_with_their_status():
    """401・404・429・503 は取得としては成功（判定は T9 の責務）。X-Audit-App の有無で TRANSIENT との境が付く。"""
    cases = {
        401: Reply(status=401, headers=(("WWW-Authenticate", 'Basic realm="x"'),), body=b""),
        404: Reply(status=404, headers=HTML, body=b"<html>nf</html>"),
        429: Reply(status=429, headers=(*HTML, ("Retry-After", "30")), body=b"slow down"),
        503: Reply(status=503, headers=(*HTML, ("X-Audit-App", "1")), body=b"busy"),
    }
    for status, reply in cases.items():
        r = await make_rig({KEY: reply}).fetch.fetch(req())
        assert (r.outcome, r.status) == (FetchOutcome.OK, status)
    r401 = await make_rig({KEY: cases[401]}).fetch.fetch(req())
    assert r401.headers["www-authenticate"].startswith("Basic") and r401.body == b"" and r401.content_kind is None
    assert (await make_rig({KEY: cases[503]}).fetch.fetch(req())).has_audit_app_header is True
    assert (await make_rig({KEY: cases[429]}).fetch.fetch(req())).has_audit_app_header is False


async def test_empty_bodies_do_not_need_a_content_type():
    for reply in (Reply(status=204, headers=(), body=b""), Reply(status=200, headers=(), body=b"")):
        r = await make_rig({KEY: reply}).fetch.fetch(req())
        assert (r.outcome, r.body, r.content_kind) == (FetchOutcome.OK, b"", None)


# ---------------------------------------------------------------- サイズ
async def test_page_body_at_the_cap_is_not_truncated_one_byte_more_is():
    cap = FETCH_LIMITS.max_decoded_bytes
    at = Reply(headers=HTML, repeat=(b"a" * 1024, cap // 1024))
    r = await make_rig({KEY: at}).fetch.fetch(req())
    assert (len(r.body), r.truncated, r.limit_hit) == (cap, False, None)
    over = Reply(headers=HTML, repeat=(b"a" * (1024 + 1), cap // 1024))  # cap より 1024 バイト多い
    r2 = await make_rig({KEY: over}).fetch.fetch(req())
    assert (len(r2.body), r2.truncated, r2.limit_hit) == (cap, True, FetchLimit.DECODED_SIZE)


async def test_chunked_bodies_are_read_and_capped_like_any_other():
    cap = FETCH_LIMITS.max_decoded_bytes
    r = await make_rig({KEY: Reply(headers=HTML, chunked=True, body=b"<html>chunked</html>")}).fetch.fetch(req())
    assert r.body == b"<html>chunked</html>" and r.truncated is False
    r2 = await make_rig({KEY: Reply(headers=HTML, chunked=True, repeat=(b"b" * 4096, cap // 4096 + 5))}).fetch.fetch(req())
    assert (len(r2.body), r2.truncated, r2.limit_hit) == (cap, True, FetchLimit.DECODED_SIZE)


async def test_probe_mode_reads_only_the_first_64kb_even_when_content_length_is_huge():
    prefix = FETCH_LIMITS.probe_prefix_bytes
    big = Reply(headers=HTML, body=b"p" * (prefix * 3), content_length=10 * 1024 * 1024)
    r = await make_rig({KEY: big}).fetch.fetch(req(mode=FetchMode.PROBE))
    assert (r.outcome, r.status, len(r.body), r.truncated, r.limit_hit) == (FetchOutcome.OK, 200, prefix, True, FetchLimit.PROBE_PREFIX)
    small = Reply(headers=HTML, body=b"p" * prefix)
    r2 = await make_rig({KEY: small}).fetch.fetch(req(mode=FetchMode.PROBE))
    assert (len(r2.body), r2.truncated) == (prefix, False)
    # 同じ巨大 Content-Length でも page モードは読む前に拒否（上の probe との差）
    r3 = await make_rig({KEY: big}).fetch.fetch(req(mode=FetchMode.PAGE))
    assert (r3.outcome, r3.limit_hit, r3.body) == (FetchOutcome.TOO_LARGE, FetchLimit.CONTENT_LENGTH, b"")


# ---------------------------------------------------------------- 圧縮
async def test_gzip_and_deflate_bodies_are_decoded():
    text = b"<html>" + "圧縮された本文".encode() * 200
    rig = make_rig(
        {
            f"{SVC_HOST}/fx/g": Reply(headers=(*HTML, ("Content-Encoding", "gzip")), body=text, gzip=True),
            f"{SVC_HOST}/fx/d": Reply(headers=(*HTML, ("Content-Encoding", "deflate")), body=zlib.compress(text)),
        }
    )
    for name in ("g", "d"):
        r = await rig.fetch.fetch(req(f"https://{SVC_HOST}/fx/{name}"))
        assert (r.outcome, r.body) == (FetchOutcome.OK, text), name


async def test_corrupt_and_cut_off_compressed_bodies_are_network_errors_not_partial_data():
    good = gzip.compress(b"<html>" + b"y" * 4000)
    rig = make_rig(
        {
            f"{SVC_HOST}/fx/cut": Reply(headers=(*HTML, ("Content-Encoding", "gzip")), body=good[: len(good) // 2]),
            f"{SVC_HOST}/fx/bad": Reply(headers=(*HTML, ("Content-Encoding", "gzip")), body=b"not gzip data at all"),
        }
    )
    for name, note in (("cut", "decode.truncated"), ("bad", "decode.corrupt")):
        d = await rig.fetch.fetch_ex(req(f"https://{SVC_HOST}/fx/{name}"))
        assert (d.result.outcome, d.result.status, d.result.body) == (FetchOutcome.NETWORK_ERROR, 200, b"")
        assert note in d.notes


# ---------------------------------------------------------------- 転送
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_all_redirect_statuses_are_followed_with_get(status: int):
    rig = make_rig({KEY: Reply(status=status, headers=(("Location", "/fx/b"),)), f"{SVC_HOST}/fx/b": Reply(body=b"final")})
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.status, r.body, r.final_url) == (FetchOutcome.OK, 200, b"final", f"https://{SVC_HOST}/fx/b")
    (hop,) = r.redirects
    assert (hop.status, hop.followed, hop.in_scope, hop.blocked_policy, hop.url, hop.location) == (status, True, True, None, PAGE, "/fx/b")
    assert {s.method for s in rig.net.requests} == {"GET"}


@pytest.mark.parametrize("status", [300, 304, 305])
async def test_non_redirect_3xx_statuses_are_final_responses(status: int):
    rig = make_rig({KEY: Reply(status=status, headers=(("Location", "/fx/b"),), body=b"")})
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.status, r.redirects) == (FetchOutcome.OK, status, ())
    assert len(rig.net.requests) == 1


async def test_a_redirect_without_location_is_the_final_response():
    r = await make_rig({KEY: Reply(status=302, headers=())}).fetch.fetch(req())
    assert (r.outcome, r.status) == (FetchOutcome.OK, 302)
    (hop,) = r.redirects
    assert (hop.followed, hop.blocked_policy, hop.location) == (False, None, None)


@pytest.mark.parametrize(
    ("location", "final_key"),
    [
        ("/fx/b", f"{SVC_HOST}/fx/b"),
        ("b", f"{SVC_HOST}/fx/b"),  # 相対（現在のパスの続き）
        ("../fx/c", f"{SVC_HOST}/fx/c"),
        (f"https://{SVC_HOST}/fx/d#frag", f"{SVC_HOST}/fx/d"),
        (f"//{SVC2_HOST}/e", f"{SVC2_HOST}/e"),  # スキーム相対でスコープ内の別ホスト
        (f"https://{SVC2_HOST}/e?x=1", f"{SVC2_HOST}/e?x=1"),
    ],
)
async def test_location_forms_are_resolved_and_each_hop_uses_its_own_host_and_pinned_ip(location: str, final_key: str):
    rig = make_rig({KEY: Reply(status=302, headers=(("Location", location),)), final_key: Reply(body=b"ok")})
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.body) == (FetchOutcome.OK, b"ok") and rig.net.unrouted == []
    last = rig.net.requests[-1]
    host = final_key.split("/")[0]
    assert last.headers["host"] == host and last.tls_hostname == host
    assert last.ip == (PUBLIC_IP_2 if host == SVC2_HOST else PUBLIC_IP)
    assert rig.net.non_ip_connects == []


async def test_three_followed_hops_are_allowed_and_the_fourth_redirect_is_not():
    chain = {f"{SVC_HOST}/fx/r{i}": Reply(status=302, headers=(("Location", f"/fx/r{i + 1}"),)) for i in range(0, 3)}
    chain[f"{SVC_HOST}/fx/r3"] = Reply(body=b"end")
    r = await make_rig(chain).fetch.fetch(req(f"https://{SVC_HOST}/fx/r0"))
    assert (r.outcome, r.body, len(r.redirects)) == (FetchOutcome.OK, b"end", 3)
    assert all(h.followed and h.in_scope for h in r.redirects)
    chain[f"{SVC_HOST}/fx/r3"] = Reply(status=302, headers=(("Location", "/fx/r4"),))
    r2 = await make_rig(chain).fetch.fetch(req(f"https://{SVC_HOST}/fx/r0"))
    assert (r2.outcome, r2.limit_hit, len(r2.redirects)) == (FetchOutcome.TOO_MANY_REDIRECTS, FetchLimit.REDIRECTS, 4)
    assert [h.followed for h in r2.redirects] == [True, True, True, False]


async def test_same_headers_on_every_hop_and_no_state_carried_over():
    rig = make_rig({KEY: Reply(status=302, headers=(("Location", "/fx/b"), ("Set-Cookie", "sid=1"))), f"{SVC_HOST}/fx/b": Reply(body=b"x")})
    await rig.fetch.fetch(req())
    first, second = rig.net.requests
    assert first.headers.keys() == second.headers.keys()
    assert "cookie" not in second.headers and "referer" not in second.headers


async def test_dns_rebinding_between_hops_is_caught_by_the_per_hop_recheck():
    """1ホップ目は公開 IP、同じホストへの転送の再解決で私有 IP が返る。ホップごとの検査で止まり、私有 IP へは接続しない。"""
    rig = make_rig(
        {KEY: Reply(status=302, headers=(("Location", "/fx/b"),)), f"{SVC_HOST}/fx/b": Reply(body=b"x")},
        dns={SVC_HOST: [[PUBLIC_IP], [PRIVATE_IP]]},
    )
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.status) == (FetchOutcome.OK, 302)
    (hop,) = r.redirects
    assert (hop.followed, hop.in_scope, hop.blocked_policy) == (False, True, PolicyId.SSRF_IP)
    assert rig.net.connected_ips == (PUBLIC_IP,) and rig.resolver.calls == {SVC_HOST: 2}
    assert r.final_url == PAGE and r.headers["location"] == "/fx/b"  # 認証壁などの証拠として Location は残る


async def test_overlong_location_is_clipped_and_blocked_without_error():
    rig = make_rig({KEY: Reply(status=302, headers=(("Location", "/fx/" + "z" * 3000),))})
    r = await rig.fetch.fetch(req())
    assert r.outcome is FetchOutcome.OK and r.redirects[-1].blocked_policy is PolicyId.SCOPE
    assert len(r.redirects[-1].location or "") <= 2048


async def test_redirect_limit_follows_the_configured_limit():
    chain = {f"{SVC_HOST}/fx/r{i}": Reply(status=302, headers=(("Location", f"/fx/r{i + 1}"),)) for i in range(0, 4)}
    r = await make_rig(chain, limits=FetchLimits(max_redirects=1)).fetch.fetch(req(f"https://{SVC_HOST}/fx/r0"))
    assert (r.outcome, len(r.redirects)) == (FetchOutcome.TOO_MANY_REDIRECTS, 2)


# ---------------------------------------------------------------- 失敗は例外でなく結果で返る
async def test_connect_errors_and_timeouts_are_results():
    rig = make_rig({KEY: Reply(body=b"x")}, connect_errors={PUBLIC_IP: httpcore.ConnectError("refused")})
    assert (await rig.fetch.fetch(req())).outcome is FetchOutcome.NETWORK_ERROR
    rig2 = make_rig({KEY: Reply(body=b"x")}, connect_errors={PUBLIC_IP: httpcore.ConnectTimeout("t")})
    r2 = await rig2.fetch.fetch(req())
    assert (r2.outcome, r2.limit_hit) == (FetchOutcome.TIMEOUT, FetchLimit.CONNECT_TIMEOUT)


async def test_failover_to_the_second_checked_ip_when_the_first_refuses():
    rig = make_rig(
        {KEY: Reply(body=b"x")},
        dns={SVC_HOST: [[PUBLIC_IP, PUBLIC_IP_2]]},
        connect_errors={PUBLIC_IP: httpcore.ConnectError("refused")},
    )
    r = await rig.fetch.fetch(req())
    assert r.outcome is FetchOutcome.OK and rig.net.connected_ips == (PUBLIC_IP, PUBLIC_IP_2)


async def test_dns_failure_is_a_network_error_not_a_block():
    rig = make_rig({KEY: Reply(body=b"x")}, dns={})
    rig.resolver.dns.pop(SVC_HOST)  # 名前が引けない
    d = await rig.fetch.fetch_ex(req())
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and d.result.blocked_policy is None
    assert d.notes == ("dns:dns.error",) and rig.net.connects == []


async def test_dns_failure_on_a_redirect_target_is_a_network_error_with_the_hop_recorded():
    rig = make_rig({KEY: Reply(status=302, headers=(("Location", f"https://{SVC2_HOST}/x"),))})
    rig.resolver.dns.pop(SVC2_HOST)
    r = await rig.fetch.fetch(req())
    assert r.outcome is FetchOutcome.NETWORK_ERROR
    (hop,) = r.redirects
    assert (hop.followed, hop.in_scope, hop.blocked_policy) == (False, True, None)


async def test_protocol_garbage_is_a_network_error():
    class Garbage(FakeInternet):
        def select(self, host, target):  # noqa: ANN001, ANN201
            plan = super().select(host, target)
            plan.items = iter([(0.0, b"this is not http\r\n\r\n")])
            return plan

    net = Garbage({KEY: Reply(body=b"x")})
    sf = SafeFetch(VECTOR_PREFIXES, resolver=FakeResolver(), network_backend=net, ssl_context=FAKE_SSL)
    r = await sf.fetch(req())
    assert r.outcome is FetchOutcome.NETWORK_ERROR


async def test_unexpected_exceptions_never_escape_fetch():
    class Boom(FakeInternet):
        async def connect_tcp(self, *a, **k):  # noqa: ANN002, ANN003, ANN201
            raise RuntimeError("boom")

    sf = SafeFetch(VECTOR_PREFIXES, resolver=FakeResolver(), network_backend=Boom(), ssl_context=FAKE_SSL)
    d = await sf.fetch_ex(req())
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and "net.unexpected" in d.notes


async def test_blocked_result_has_escaped_requested_url_and_no_state():
    bad = "https://svc.example.invalid/fx/a\nHost: evil​"
    r = await make_rig().fetch.fetch(FetchRequest(url=bad))
    assert r.outcome is FetchOutcome.BLOCKED and r.blocked_policy is PolicyId.SCOPE
    assert "\n" not in r.requested_url and "​" not in r.requested_url
    assert (r.status, r.body, r.redirects, r.headers, r.final_url) == (None, b"", (), {}, None)


# ---------------------------------------------------------------- 時間
async def test_total_deadline_covers_the_whole_redirect_chain():
    chain = {f"{SVC_HOST}/fx/r{i}": Reply(status=302, headers=(("Location", f"/fx/r{i + 1}"),), first_byte_delay_s=0.22) for i in range(0, 6)}
    r = await make_rig(chain, limits=SHORT).fetch.fetch(req(f"https://{SVC_HOST}/fx/r0"))
    assert (r.outcome, r.limit_hit) == (FetchOutcome.TIMEOUT, FetchLimit.TOTAL_TIMEOUT)
    assert 1 <= len(r.redirects) <= 3 and all(h.followed for h in r.redirects)


async def test_cancellation_is_propagated_and_not_swallowed():
    rig = make_rig({KEY: Reply(headers=HTML, infinite=b"x", chunk_delay_s=0.05)}, limits=FetchLimits(total_timeout_s=30, sock_read_timeout_s=10))
    task = asyncio.create_task(rig.fetch.fetch(req()))
    await asyncio.sleep(0.15)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_concurrent_fetches_are_independent():
    routes = {f"{SVC_HOST}/fx/p{i}": Reply(body=f"page{i}".encode()) for i in range(12)}
    rig = make_rig(routes)
    results = await asyncio.gather(*(rig.fetch.fetch(req(f"https://{SVC_HOST}/fx/p{i}")) for i in range(12)))
    assert [r.body for r in results] == [f"page{i}".encode() for i in range(12)]
    assert len(rig.net.requests) == 12 and rig.net.non_ip_connects == []


async def test_empty_scope_blocks_everything_before_dns():
    rig = make_rig({KEY: Reply(body=b"x")}, prefixes=())
    r = await rig.fetch.fetch(req())
    assert (r.outcome, r.blocked_policy) == (FetchOutcome.BLOCKED, PolicyId.SCOPE)
    assert rig.resolver.calls == {} and rig.net.connects == []


async def test_oversized_response_headers_are_a_network_error():
    """ヘッダの洪水。httpcore は未完結の頭部を 100KB までしか溜めない（1回の受信は64KB）ので、約 320KB の頭部は解析側が拒否する。"""
    flood = tuple((f"X-Pad-{i}", "p" * 200) for i in range(1500))
    d = await make_rig({KEY: Reply(headers=(*HTML, *flood), body=b"x")}).fetch.fetch_ex(req())
    assert d.result.outcome is FetchOutcome.NETWORK_ERROR and d.result.body == b""


async def test_proxy_environment_variables_are_ignored(monkeypatch: pytest.MonkeyPatch):
    """trust_env=False 相当: 環境のプロキシ指定で、検査済み IP 以外へ接続しない（HTTP クライアントを差し替えた時の退行検知）。"""
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(k, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    rig = make_rig({KEY: Reply(body=b"x")})
    assert (await rig.fetch.fetch(req())).outcome is FetchOutcome.OK
    assert rig.net.connects == [(PUBLIC_IP, 443)]
