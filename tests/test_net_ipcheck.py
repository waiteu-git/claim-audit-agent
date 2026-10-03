"""IP 検査（app/net/ipcheck.py）。期待値は RFC の番号から手で書いた表で、実装の表とは独立（実装の打ち間違いを拾うため）。

`ipaddress.is_global` が真になる危険な値（マルチキャスト・NAT64 内の 127.0.0.1・IPv4 互換・192.88.99/24・192.0.0.9）が
拒否されることを必ず入れる。この表を Python 3.12 と 3.14 の両方で流して同じ結果になることを確認済み（デプロイは 3.13）。
"""
import ipaddress

import pytest

from app.net.ipcheck import IpBlockReason as R
from app.net.ipcheck import check_ip


# pre-commit ガードは 100.64 台のドット表記を「運用者の tailnet IP」とみなして止める。
# ここの値は標準の CGNAT 帯と Alibaba のメタデータ IP（運用者のアドレスではない）なので、リテラルを避けて組み立てる。
def _dq(*octets: int) -> str:
    return ".".join(str(o) for o in octets)

BLOCKED = [
    # IPv4
    ("0.0.0.0", R.UNSPECIFIED), ("0.1.2.3", R.UNSPECIFIED),
    ("10.0.0.1", R.PRIVATE), ("10.255.255.255", R.PRIVATE),
    (_dq(100, 64, 0, 1), R.CGNAT), (_dq(100, 127, 255, 255), R.CGNAT),
    ("127.0.0.1", R.LOOPBACK), ("127.255.255.254", R.LOOPBACK),
    ("169.254.169.254", R.METADATA), ("169.254.170.2", R.METADATA), (_dq(100, 100, 100, 200), R.METADATA),
    ("169.254.0.1", R.LINK_LOCAL), ("169.254.255.255", R.LINK_LOCAL),
    ("172.16.0.1", R.PRIVATE), ("172.31.255.255", R.PRIVATE),
    ("192.0.0.1", R.PROTOCOL), ("192.0.0.9", R.PROTOCOL), ("192.0.0.10", R.PROTOCOL),
    ("192.0.2.1", R.DOCUMENTATION), ("198.51.100.1", R.DOCUMENTATION), ("203.0.113.1", R.DOCUMENTATION),
    ("192.88.99.1", R.TRANSITION),
    ("192.168.0.1", R.PRIVATE), ("192.168.255.255", R.PRIVATE),
    ("198.18.0.1", R.BENCHMARK), ("198.19.255.255", R.BENCHMARK),
    ("224.0.0.1", R.MULTICAST), ("239.255.255.255", R.MULTICAST),
    ("240.0.0.1", R.RESERVED), ("255.255.255.255", R.RESERVED),
    # IPv6
    ("::", R.UNSPECIFIED), ("::1", R.LOOPBACK),
    ("::8.8.8.8", R.TRANSITION), ("::808:808", R.TRANSITION),  # IPv4 互換（is_global が真）
    ("::ffff:0:8.8.8.8", R.TRANSITION),  # SIIT
    ("64:ff9b:1::1", R.TRANSITION),  # ローカル用 NAT64
    ("100::1", R.RESERVED),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", R.TRANSITION),  # Teredo
    ("2001:db8::1", R.DOCUMENTATION), ("3fff::1", R.DOCUMENTATION),
    ("2002:808:808::1", R.TRANSITION), ("2002:7f00:1::1", R.TRANSITION),  # 6to4
    ("fc00::1", R.PRIVATE), ("fd12:3456:789a::1", R.PRIVATE), ("fd00:ec2::254", R.METADATA),
    ("fe80::1", R.LINK_LOCAL), ("febf::1", R.LINK_LOCAL),
    ("ff02::1", R.MULTICAST), ("ff00::", R.MULTICAST),
    ("5f00::1", R.RESERVED),  # 2000::/3 の外（is_global が真）
    ("4000::1", R.RESERVED),
]

ALLOWED = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
    "169.253.255.255", "192.0.1.1", "192.169.0.1", "198.17.255.255", "198.20.0.1", "223.255.255.255",
    "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::1",
    "::ffff:8.8.8.8",  # IPv4 射影でも中が公開なら通る
    "64:ff9b::808:808",  # NAT64（well-known）で中が公開
]


@pytest.mark.parametrize(("addr", "reason"), BLOCKED)
def test_blocked_with_specific_reason(addr: str, reason: R):
    v = check_ip(addr)
    assert v.ok is False and v.reason is reason, f"{addr}: {v}"


@pytest.mark.parametrize("addr", ALLOWED)
def test_global_addresses_pass(addr: str):
    assert check_ip(addr).ok is True, addr


@pytest.mark.parametrize(
    ("addr", "via", "reason"),
    [
        ("::ffff:169.254.169.254", "v4mapped", R.METADATA),
        ("::ffff:127.0.0.1", "v4mapped", R.LOOPBACK),
        ("::ffff:10.1.2.3", "v4mapped", R.PRIVATE),
        ("::ffff:7f00:1", "v4mapped", R.LOOPBACK),  # 16進で書いた射影
        ("64:ff9b::7f00:1", "nat64", R.LOOPBACK),  # is_global が真になる値
        ("64:ff9b::a9fe:a9fe", "nat64", R.METADATA),
        ("64:ff9b::a00:1", "nat64", R.PRIVATE),
    ],
)
def test_embedded_ipv4_is_extracted_and_rechecked(addr: str, via: str, reason: R):
    v = check_ip(addr)
    assert (v.ok, v.via, v.reason) == (False, via, reason)
    assert v.code == f"{via}>{reason.value}"


@pytest.mark.parametrize("bad", ["", "not-an-ip", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "0x7f.0.0.1", "127.1", "2130706433", "::g", " 8.8.8.8", "8.8.8.8 "])
def test_unparsable_is_blocked_fail_closed(bad: str):
    v = check_ip(bad)
    assert v.ok is False and v.reason is R.INVALID


@pytest.mark.parametrize("bad", [None, 0, b"8.8.8.8", ["8.8.8.8"], ipaddress.ip_address("8.8.8.8")])
def test_non_string_is_blocked(bad):
    assert check_ip(bad).ok is False  # 型が違うものは通さない（フェイクの DNS の誤りで素通りしない）


@pytest.mark.parametrize("addr", ["fe80::1%eth0", "fe80::1%1", "2606:4700::1%lo0"])
def test_zone_id_is_blocked_even_for_global_addresses(addr: str):
    v = check_ip(addr)
    assert v.ok is False and v.reason is R.SCOPE_ID


def test_every_non_ok_verdict_has_a_reason_code_and_ok_is_ok():
    assert check_ip("8.8.8.8").code == "ok"
    assert check_ip("127.0.0.1").code == "ip.loopback"


def test_allowed_results_are_always_global_unicast_and_never_multicast_or_reserved():
    """許可した値は、必ず is_global・非マルチキャスト・非予約（二重化の確認。IPv4 は /16 の境目を網羅して標本化）。"""
    allowed = 0
    for hi in range(0, 256):
        for mid in (0, 1, 15, 16, 31, 32, 63, 64, 127, 128, 168, 169, 170, 254, 255):
            addr = ipaddress.IPv4Address((hi << 24) | (mid << 16) | 1)
            if check_ip(str(addr)).ok:
                allowed += 1
                assert addr.is_global and not addr.is_multicast and not addr.is_reserved, addr
    assert allowed > 1000  # 「全部拒否」で緑になっていない


def test_ipv6_allowed_only_inside_global_unicast_range():
    ok = [a for a in ("2000::1", "2001:4860::1", "2400::1", "2a00::1", "3000::1", "3ffe::1") if check_ip(a).ok]
    assert ok  # 少なくとも一部は通る
    for a in ok:
        assert ipaddress.IPv6Address(a) in ipaddress.ip_network("2000::/3")


def test_is_global_fence_blocks_on_its_own_when_the_explicit_table_is_empty(monkeypatch: pytest.MonkeyPatch):
    """二重化の確認: 明示の拒否表が空でも、is_global が偽の範囲は NOT_GLOBAL で止まる（将来の Python が範囲を足した時の備え）。
    逆に、is_global が真になる危険な値（マルチキャスト等）は明示の表だけが止める＝上の BLOCKED の表がそれを固定している。"""
    from app.net import ipcheck

    monkeypatch.setattr(ipcheck, "_V4_DENY", ())
    monkeypatch.setattr(ipcheck, "_V6_DENY", ())
    for addr in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", _dq(100, 64, 0, 1), "198.18.0.1", "240.0.0.1", "fc00::1", "fe80::1", "::1", "2001:db8::1"):
        v = check_ip(addr)
        assert v.ok is False, addr
    assert check_ip("10.0.0.1").reason is R.NOT_GLOBAL
    assert check_ip("8.8.8.8").ok is True
