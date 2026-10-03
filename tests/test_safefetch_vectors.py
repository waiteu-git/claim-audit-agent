"""SafeFetch の敵対ベクタ（app/net/vectors.py）を全部流して、期待どおりに拒否・打切りされることを確かめる。

Gate2 条件⑤「SSRF ベクタ15本が全て deny」。ここでは 15 を超えて持つ（tier 2 が Gate2 分）。
拒否の試験は「何も通らない環境」でも緑になるので、(1) 拒否の理由コードまで照合する（別の理由で止まって緑になるのを防ぐ）、
(2) 偽のネットワーク層で、拒否したベクタの IP に接続していないことを見る、(3) 通るべき書き方（陽性対照）が通ることを見る。
"""
import asyncio

import pytest

from app.config import FetchLimits
from app.contracts import FetchOutcome, FetchRequest, FetchResult
from app.net.vectors import (
    ALL_VECTORS,
    GATE2_VECTORS,
    POSITIVE_CONTROLS,
    VECTOR_LIMITS_KW,
    VECTOR_PREFIXES,
    Vector,
)
from tests.net_support import make_rig


async def _run(v: Vector):
    limits = FetchLimits(**{**VECTOR_LIMITS_KW, **v.limits_kw})
    rig = make_rig(v.replies, dns=v.dns, limits=limits, prefixes=VECTOR_PREFIXES)
    # 上限を壊した実装でハングして試験全体が止まらないよう、外側にも期限を置く（本物の期限は SafeFetch の中）
    detail = await asyncio.wait_for(rig.fetch.fetch_ex(FetchRequest(url=v.url)), timeout=10)
    return rig, detail


def _check(v: Vector, rig, detail) -> None:
    r: FetchResult = detail.result
    e = v.expect
    assert r.outcome is e.outcome, f"{v.id}: outcome={r.outcome} notes={detail.notes}"
    assert r.blocked_policy is e.blocked_policy, f"{v.id}: policy={r.blocked_policy} notes={detail.notes}"
    if e.status is not None:
        assert r.status == e.status
    if e.hop_policy is not None:
        assert r.redirects and r.redirects[-1].followed is False
        assert r.redirects[-1].blocked_policy is e.hop_policy
    if e.note is not None:
        assert any(e.note in n for n in detail.notes), f"{v.id}: 期待の理由 {e.note!r} が notes にない: {detail.notes}"
    if e.limit_hit is not None:
        assert r.limit_hit is e.limit_hit
    assert r.truncated is e.truncated
    if e.body_max is not None:
        assert len(r.body) <= e.body_max
    if e.connects is not None:
        assert rig.net.connected_ips == e.connects, f"{v.id}: 接続先 {rig.net.connected_ips}"
    if e.resolver_calls is not None:
        assert rig.resolver.calls == dict(e.resolver_calls), f"{v.id}: 名前解決 {rig.resolver.calls}"
    # どのベクタでも: 名前での接続（ピン留めの破れ）・拒否対象の IP への接続は 0
    assert rig.net.non_ip_connects == []
    for ip in v.never_connect:
        assert ip not in rig.net.connected_ips, f"{v.id}: 接続してはいけない {ip} へ接続した"


@pytest.mark.parametrize("v", ALL_VECTORS, ids=lambda v: v.id)
async def test_vector_is_denied_as_expected(v: Vector):
    rig, detail = await _run(v)
    _check(v, rig, detail)
    # 拒否系は、本文を1バイトも返さない（打切りの gzip 爆弾だけが 1MiB までの本文を持つ）
    if v.expect.outcome is FetchOutcome.BLOCKED:
        assert detail.result.body == b"" and detail.result.status is None


@pytest.mark.parametrize("v", POSITIVE_CONTROLS, ids=lambda v: v.id)
async def test_positive_control_passes(v: Vector):
    """通るべき書き方が通る＝この環境は「何でも拒否する」わけではない。"""
    rig, detail = await _run(v)
    _check(v, rig, detail)
    assert detail.result.body != b"" and rig.net.unrouted == []


def test_gate2_has_at_least_fifteen_vectors_and_they_are_unique():
    ids = [v.id for v in (*ALL_VECTORS, *POSITIVE_CONTROLS)]
    assert len(ids) == len(set(ids))
    assert len(GATE2_VECTORS) >= 15
    assert all(v.tier in (2, 3) for v in ALL_VECTORS)


def test_vectors_cover_every_family_the_gate_asks_for():
    """Gate2 が名指しする種類が tier 2 に1つずつ在る（ベクタを消しても気づけるように）。"""
    t2 = {v.id for v in GATE2_VECTORS}
    for needed in (
        "url-metadata-ip-literal", "url-metadata-hostname", "url-loopback-v4", "url-loopback-v6",
        "url-ip-decimal", "url-ip-hex", "url-ip-octal", "url-userinfo", "url-port-8443", "url-file-scheme",
        "scope-outside-host", "redirect-to-metadata-literal", "redirect-to-host-resolving-private",
        "dns-mixed-public-private", "dns-v4-mapped-metadata", "dns-rebinding-public-then-private",
        "body-gzip-bomb", "body-huge-content-length", "body-slow-drip", "type-octet-stream",
    ):
        assert needed in t2, needed


def test_s07_vectors_are_present():
    """設計 §5-3 の S-07: 配信側の1本（クエリ付き /fx/ は 404）を除く6本。"""
    ids = {v.id for v in ALL_VECTORS}
    assert {
        "s07-dotdot-out-of-scope", "s07-encoded-dotdot", "s07-encoded-slash",
        "s07-prefix-not-segment", "s07-host-suffix-confusion", "s07-host-at-evil",
    } <= ids
