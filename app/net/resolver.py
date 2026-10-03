"""GuardedResolver（設計 §5-3）。名前解決の全応答を検査し、1つでも非グローバルなら全体を拒否する。

公開 IP と私有 IP が混ざった応答で逃がさない（片方だけ使えば通る、という抜け道を作らない）。
返すのは検査済みの IP だけで、接続は PinnedBackend がその IP にだけ行う（再解決しない＝DNS リバインディングの隙を閉じる）。

解決関数は注入できる（テストは完全オフラインでフェイクを使う）。既定の system_resolver だけが実際の DNS を引く。

system_resolver の資源の扱い（敵対レビューで追加）: getaddrinfo はスレッドで走り、呼び出し側が期限で諦めてもスレッドは止まらない。
既定のスレッドプールは小さい（1 vCPU で5本）うえ他の用途と共有なので、応答しない名前を数回引くだけで、別の名前の解決・他の処理まで
詰まる。そこで (1) 専用のプールで引く、(2) 同じ名前の引き直しは、走っている1本に合流する（スレッドを増やさない。終われば忘れる＝
キャッシュではない）。使うスレッドは「同時に詰まった名前の数」以下に収まる。
"""
import asyncio
import socket
import weakref
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor

from app.net.ipcheck import IpVerdict, check_ip

# host（IDNA 済みの ASCII）→ そのホストの全 IP 文字列（A と AAAA）。
HostResolver = Callable[[str], Awaitable[Sequence[str]]]

DEFAULT_RESOLVE_TIMEOUT_S = 3.0
DEFAULT_MAX_ADDRESSES_TRIED = 4  # 検査は全件、接続を試すのは先頭のこの件数まで


class ResolveFailed(Exception):
    """名前解決そのものの失敗（応答なし・タイムアウト・DNS エラー）。NETWORK_ERROR にあたる。"""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code  # "dns.timeout" / "dns.no_answer" / "dns.error"


class IpBlocked(Exception):
    """応答のどれかが非グローバルだった。verdict は最初に見つかった拒否（P-SSRF-IP-01 にあたる）。"""

    def __init__(self, verdict: IpVerdict) -> None:
        super().__init__(verdict.code)  # メッセージに生の IP は入れない
        self.verdict = verdict


_DNS_WORKERS = 8  # 同時に引く名前の数の上限（取得スコープのホストは数個）。合流があるので、1つの名前では1本しか使わない
_dns_executor: ThreadPoolExecutor | None = None
# ループごとの「いま引いている名前 → その Future」。ループの寿命に合わせて消える（弱参照）
_INFLIGHT: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Future[list[str]]]]" = weakref.WeakKeyDictionary()


def _executor() -> ThreadPoolExecutor:
    global _dns_executor  # noqa: PLW0603
    if _dns_executor is None:
        _dns_executor = ThreadPoolExecutor(max_workers=_DNS_WORKERS, thread_name_prefix="safefetch-dns")
    return _dns_executor


def _lookup(fqdn: str) -> list[str]:
    """（専用スレッドで）getaddrinfo。IPv4・IPv6 の全応答を重複なしで返す。"""
    infos = socket.getaddrinfo(fqdn, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    out: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in out:
            out.append(sockaddr[0])
    return out


async def system_resolver(host: str) -> Sequence[str]:
    """実際の DNS（getaddrinfo）。IPv4・IPv6 の全応答を重複なしで返す。"""
    loop = asyncio.get_running_loop()
    # 絶対名（末尾ドット）で引く。付けないと resolv.conf の search（Cloud Run では *.internal 系）や ndots で、検査した名前とは
    # 別の名前（svc.example.invalid.<project>.internal など）へ展開されうる。引く名前＝検査・スコープ照合した名前にする
    fqdn = host if host.endswith(".") else f"{host}."
    try:
        inflight = _INFLIGHT.setdefault(loop, {})
    except TypeError:  # 弱参照できないループ実装。合流なしで続ける（専用プールは使う）
        inflight = {}
    fut = inflight.get(fqdn)
    if fut is None:
        fut = loop.run_in_executor(_executor(), _lookup, fqdn)
        inflight[fqdn] = fut

        def _forget(f: "asyncio.Future[list[str]]", table=inflight, key=fqdn) -> None:  # noqa: ANN001
            if table.get(key) is f:
                del table[key]
            if not f.cancelled():
                f.exception()  # 誰も待っていなくても「取り出されなかった例外」の警告にしない

        fut.add_done_callback(_forget)
    return await asyncio.shield(fut)  # 待つ側が期限で諦めても、共有の Future（と走っているスレッド）は止めない


class GuardedResolver:
    def __init__(
        self,
        resolver: HostResolver = system_resolver,
        *,
        timeout_s: float = DEFAULT_RESOLVE_TIMEOUT_S,
        max_addresses_tried: int = DEFAULT_MAX_ADDRESSES_TRIED,
    ) -> None:
        self._resolver = resolver
        self._timeout_s = timeout_s
        self._max_tried = max_addresses_tried

    async def resolve(self, host: str) -> tuple[str, ...]:
        """host を解決し、全応答を検査して、接続に使ってよい IP を返す（IPv4 を先に）。

        例外: ResolveFailed（DNS の失敗）／IpBlocked（応答に非グローバルが1つでも）。
        """
        try:
            async with asyncio.timeout(self._timeout_s):
                answers = await self._resolver(host)
        except TimeoutError as e:
            raise ResolveFailed("dns.timeout") from e
        except Exception as e:  # noqa: BLE001 gaierror 等。理由は非公開ログ側で分かれば足りる
            raise ResolveFailed("dns.error") from e
        unique: list[str] = []
        for a in answers or ():
            if a not in unique:
                unique.append(a)
        if not unique:
            raise ResolveFailed("dns.no_answer")
        for a in unique:  # 全件を検査。使わない分も含めて1つでも悪ければ全体拒否
            verdict = check_ip(a)
            if not verdict.ok:
                raise IpBlocked(verdict)
        v4 = [a for a in unique if ":" not in a]
        v6 = [a for a in unique if ":" in a]
        return tuple((v4 + v6)[: self._max_tried])
