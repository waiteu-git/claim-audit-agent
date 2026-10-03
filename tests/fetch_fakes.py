"""FetchPort のフェイクと FetchResult の組み立て（T9 のテスト用）。通信しない。

T3（SafeFetch）が出来るまでの代用で、契約（FetchResult の不変条件）に従う。実装済みの FetchPort が出来ても、
http_probe は FetchPort の Protocol にだけ依存するので、このフェイクで試験を続けられる。
"""
from collections.abc import Callable
from typing import Any

from app.contracts import (
    ContentKind,
    FetchLimit,
    FetchMode,
    FetchOutcome,
    FetchRequest,
    FetchResult,
    PolicyId,
    RedirectHop,
)

HOST = "svc.example.invalid"  # 実在しない TLD。テストの URL はすべて *.example.invalid
SUB_URL = f"https://{HOST}/fx/defect/submission/"
LOGIN_URL = f"https://{HOST}/fx/defect/login/"
RUN_APP = "." + "run" + ".app"  # 実在サービスの形を連結で組む（ソースに run.app 系ホストを書かない。test_layout の規約）
CLOUD_RUN_URL = "https://demo-submission" + RUN_APP + "/"

HTML_HEADERS = {"content-type": "text/html; charset=utf-8"}
_UNSET: Any = object()


def html(body: str) -> bytes:
    return body.encode("utf-8")


def make_result(
    url: str = SUB_URL,
    *,
    outcome: FetchOutcome = FetchOutcome.OK,
    status: int | None = _UNSET,
    headers: dict[str, str] | None = None,
    body: bytes | str = b"",
    redirects: tuple[RedirectHop, ...] = (),
    final_url: str | None = None,
    content_kind: ContentKind | None = ContentKind.HTML,
    elapsed_ms: int = 120,
    **kw: Any,
) -> FetchResult:
    """契約の不変条件を満たす FetchResult。status の既定は ok なら 200、それ以外は None。"""
    raw = body.encode("utf-8") if isinstance(body, str) else body
    hdrs = HTML_HEADERS if headers is None else headers
    if status is _UNSET:
        status = 200 if outcome is FetchOutcome.OK else None
    return FetchResult(
        requested_url=url,
        final_url=final_url if final_url is not None else (url if outcome is FetchOutcome.OK else None),
        redirects=redirects,
        outcome=outcome,
        status=status,
        headers=hdrs,
        body=raw,
        content_kind=content_kind,
        elapsed_ms=elapsed_ms,
        **kw,
    )


def redirect(
    frm: str = SUB_URL,
    location: str = "/fx/defect/login/",
    status: int = 302,
    *,
    followed: bool = True,
    in_scope: bool = True,
    blocked_policy: PolicyId | None = None,
) -> RedirectHop:
    return RedirectHop(
        url=frm,
        status=status,
        location=location,
        followed=followed,
        in_scope=in_scope if followed else False,
        blocked_policy=blocked_policy,
    )


def timeout_result(url: str = SUB_URL) -> FetchResult:
    return make_result(url, outcome=FetchOutcome.TIMEOUT, limit_hit=FetchLimit.TOTAL_TIMEOUT, content_kind=None, headers={})


def network_error_result(url: str = SUB_URL) -> FetchResult:
    return make_result(url, outcome=FetchOutcome.NETWORK_ERROR, content_kind=None, headers={})


class FakeFetchPort:
    """台本どおりに返す FetchPort。要求を calls に残す。台本が尽きたら最後の1つを返し続ける。

    台本の要素は FetchResult、例外のインスタンス（投げる）、または FetchRequest → FetchResult の関数。
    """

    def __init__(self, *script: FetchResult | BaseException | Callable[[FetchRequest], FetchResult]) -> None:
        if not script:
            raise ValueError("台本が空です")
        self._script = list(script)
        self.calls: list[FetchRequest] = []

    async def fetch(self, request: FetchRequest) -> FetchResult:
        self.calls.append(request)
        item = self._script.pop(0) if len(self._script) > 1 else self._script[0]
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(request)
        return item

    @property
    def modes(self) -> list[FetchMode]:
        return [c.mode for c in self.calls]


class SleepRecorder:
    """待ち時間を実際には待たず、呼ばれた秒数を残す（http_probe の sleep に注入する）。"""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
