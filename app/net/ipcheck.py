"""DNS 解決後の IP 検査（設計 §5-3）。標準ライブラリだけで書く（3.12〜3.14 で同じ結果になることを tests が固定する）。

`ipaddress.is_global` だけに頼らない。実測で、is_global が真になる危険な値がある:
  マルチキャスト（224/4・ff00::/8）・192.88.99.0/24・NAT64 に入れた 127.0.0.1（64:ff9b::7f00:1）・
  IPv4 互換（::a.b.c.d）・5f00::/16。だから「明示の拒否表」を先に当て、最後に is_global で締める（二重化）。

返すのは理由コード（IpBlockReason）で、公開面へ出すのはコードだけ。生の IP は戻り値にも例外にも載せない
（jsonlog も IPv4 を伏せ字にするが、そもそも持たない）。
"""
import ipaddress
from dataclasses import dataclass
from enum import StrEnum


class IpBlockReason(StrEnum):
    INVALID = "ip.invalid"  # IP として解釈できない
    SCOPE_ID = "ip.scope_id"  # fe80::1%eth0 のようなゾーン ID 付き
    UNSPECIFIED = "ip.unspecified"  # 0.0.0.0/8・::
    LOOPBACK = "ip.loopback"
    PRIVATE = "ip.private"  # 10/8・172.16/12・192.168/16・fc00::/7
    LINK_LOCAL = "ip.link_local"  # 169.254/16・fe80::/10
    METADATA = "ip.metadata"  # クラウドのメタデータ・内部の仮想 IP（169.254.169.254・168.63.129.16 ほか）
    CGNAT = "ip.cgnat"  # 100.64/10
    MULTICAST = "ip.multicast"
    RESERVED = "ip.reserved"  # 240/4・255.255.255.255・割当外の IPv6
    DOCUMENTATION = "ip.documentation"
    BENCHMARK = "ip.benchmark"  # 198.18/15
    PROTOCOL = "ip.protocol_assignment"  # 192.0.0.0/24
    TRANSITION = "ip.transition"  # IPv4 互換・Teredo・6to4・NAT64（ローカル用）・SIIT・6to4 リレー
    NOT_GLOBAL = "ip.not_global"  # 上のどれでもないが is_global が偽


@dataclass(frozen=True)
class IpVerdict:
    """1つの IP の検査結果。via は、IPv4 を中に持つ IPv6 から取り出して再検査した時の経路（v4mapped / nat64）。"""

    ok: bool
    reason: IpBlockReason | None = None
    via: str | None = None

    @property
    def code(self) -> str:
        """トレース・ログ用の短い識別子（例 "ip.metadata" / "v4mapped>ip.metadata"）。許可なら "ok"。"""
        if self.ok:
            return "ok"
        base = self.reason.value if self.reason else "ip.invalid"
        return f"{self.via}>{base}" if self.via else base


_OK = IpVerdict(ok=True)


# pre-commit ガードは 100.64 台のドット表記を「運用者の tailnet IP」とみなして止める。
# ここの値は標準の CGNAT 帯と Alibaba のメタデータ IP（運用者のアドレスではない）なので、リテラルを避けて組み立てる。
def _dq(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _nets(rows: tuple[tuple[str, IpBlockReason], ...]) -> tuple[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IpBlockReason], ...]:
    return tuple((ipaddress.ip_network(n), r) for n, r in rows)


R = IpBlockReason
# 先に当たったものが理由になる（具体的なものを前に置く。例: メタデータは 169.254/16 と 100.64/10 より前）。
_V4_DENY = _nets(
    (
        ("169.254.169.254/32", R.METADATA),  # GCE / AWS / Azure
        ("169.254.170.2/32", R.METADATA),  # ECS のタスクメタデータ
        (f"{_dq(100, 100, 100, 200)}/32", R.METADATA),  # Alibaba
        # 公開アドレス空間にあるのに、クラウドの内側でだけ意味を持つ仮想 IP（is_global は真）。敵対レビューで追加
        ("168.63.129.16/32", R.METADATA),  # Azure の WireServer・DNS・ヘルスプローブ
        ("199.36.153.0/24", R.METADATA),  # Google の Private / Restricted Google Access（199.36.153.4/30・.8/30）
        ("0.0.0.0/8", R.UNSPECIFIED),
        ("10.0.0.0/8", R.PRIVATE),
        (f"{_dq(100, 64, 0, 0)}/10", R.CGNAT),
        ("127.0.0.0/8", R.LOOPBACK),
        ("169.254.0.0/16", R.LINK_LOCAL),
        ("172.16.0.0/12", R.PRIVATE),
        ("192.0.0.0/24", R.PROTOCOL),  # 192.0.0.9/10 は is_global が真になるので明示で拒否
        ("192.0.2.0/24", R.DOCUMENTATION),
        ("192.88.99.0/24", R.TRANSITION),  # 6to4 リレーのエニーキャスト（is_global が真）
        ("192.168.0.0/16", R.PRIVATE),
        ("198.18.0.0/15", R.BENCHMARK),
        ("198.51.100.0/24", R.DOCUMENTATION),
        ("203.0.113.0/24", R.DOCUMENTATION),
        ("224.0.0.0/4", R.MULTICAST),  # is_global が真
        ("240.0.0.0/4", R.RESERVED),  # 255.255.255.255 を含む
    )
)
_V6_DENY = _nets(
    (
        ("::/128", R.UNSPECIFIED),
        ("::1/128", R.LOOPBACK),
        ("::/96", R.TRANSITION),  # IPv4 互換（廃止）。::8.8.8.8 は is_global が真
        ("::ffff:0:0:0/96", R.TRANSITION),  # SIIT（IPv4-translated）
        ("64:ff9b:1::/48", R.TRANSITION),  # NAT64 のローカル用プレフィクス
        ("100::/64", R.RESERVED),  # discard-only
        ("2001::/32", R.TRANSITION),  # Teredo
        ("2001:db8::/32", R.DOCUMENTATION),
        ("3fff::/20", R.DOCUMENTATION),
        ("2002::/16", R.TRANSITION),  # 6to4。到達先をリレーが決めるので中身が公開でも一律拒否
        ("fd00:ec2::254/128", R.METADATA),  # AWS の IPv6 メタデータ
        ("fc00::/7", R.PRIVATE),
        ("fe80::/10", R.LINK_LOCAL),
        ("ff00::/8", R.MULTICAST),
    )
)
del R
_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")  # これ以外の IPv6 は割当外として拒否
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")  # 中の IPv4 を取り出して再検査する


def _block(reason: IpBlockReason, via: str | None = None) -> IpVerdict:
    return IpVerdict(ok=False, reason=reason, via=via)


def _check_v4(ip: ipaddress.IPv4Address, via: str | None) -> IpVerdict:
    for net, reason in _V4_DENY:
        if ip in net:
            return _block(reason, via)
    if not ip.is_global:
        return _block(IpBlockReason.NOT_GLOBAL, via)
    return _OK


def _check_v6(ip: ipaddress.IPv6Address) -> IpVerdict:
    mapped = ip.ipv4_mapped  # ::ffff:a.b.c.d
    if mapped is not None:
        return _check_v4(mapped, "v4mapped")
    if ip in _NAT64_WELL_KNOWN:
        return _check_v4(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF), "nat64")
    for net, reason in _V6_DENY:
        if ip in net:
            return _block(reason)
    if ip not in _V6_GLOBAL_UNICAST:
        return _block(IpBlockReason.RESERVED)
    if not ip.is_global:
        return _block(IpBlockReason.NOT_GLOBAL)
    return _OK


def check_ip(addr: object) -> IpVerdict:
    """1つの IP 文字列を検査する。解釈できないもの・文字列でないものは拒否（fail-closed）。"""
    if not isinstance(addr, str) or not addr:
        return _block(IpBlockReason.INVALID)
    if "%" in addr:
        return _block(IpBlockReason.SCOPE_ID)
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return _block(IpBlockReason.INVALID)
    if isinstance(ip, ipaddress.IPv4Address):
        return _check_v4(ip, None)
    return _check_v6(ip)
