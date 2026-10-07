"""RemoteFetch: FetchPort のもう1つの実装（S2 → S3 fetcher）。FETCH_MODE=remote の公開面が使う（設計 §2）。

公開面（S2）は外へ直接取りに行かない。要求（FetchRequest）を fetcher（S3・別サービス・別のサービスアカウント）へ送り、
fetcher が自分の許可リスト（ALLOWED_PREFIXES）で SafeFetch をやり直した結果（FetchResult）だけを受け取る。
ここでは URL を検査しない（検査は fetcher の責務。S2 が乗っ取られても、S3 の許可リストの外は取れない＝二重の境界）。

  * 認証: Authorization: Bearer <ID token>。token_provider は注入できる（既定は Cloud Run のメタデータサーバーから
    fetcher の URL を audience にした ID token を取る）。
  * 送受信: post（注入できる）。既定は httpcore で fetcher の /fetch へ POST する（接続は使い回さない）。
  * 応答は契約の FetchResult として厳密に検証する（extra=forbid・不変条件）。形が違う・要求と別の URL・4xx/5xx・通信失敗は
    例外にせず NETWORK_ERROR の FetchResult にする（取得の想定内の失敗。呼び出し側は確認不能の材料にする）。
"""
import json
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import httpcore
from pydantic import ValidationError

from app.contracts import FetchOutcome, FetchRequest, FetchResult
from app.jsonlog import log_event

PostFn = Callable[[str, bytes, dict[str, str]], Awaitable[tuple[int, bytes]]]
TokenProvider = Callable[[], Awaitable[str]]

FETCH_PATH = "/fetch"
METADATA_IDENTITY_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # FetchResult の本文（1MiB）を base64 にした大きさ＋余裕
CLIENT_TIMEOUT_S = 12.0  # fetcher 側の1回の取得（8秒）＋余裕


async def _httpcore_post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:  # pragma: no cover - 実通信
    async with httpcore.AsyncConnectionPool(max_keepalive_connections=0, retries=0) as pool:
        ext = {"timeout": {"connect": 3.0, "read": CLIENT_TIMEOUT_S, "write": 3.0, "pool": 3.0}}
        resp = await pool.request("POST", url, headers=list(headers.items()), content=body, extensions=ext)
        return resp.status, resp.content[: MAX_RESPONSE_BYTES + 1]


def metadata_token_provider(audience: str) -> TokenProvider:  # pragma: no cover - 実通信（Cloud Run の中だけで動く）
    async def provide() -> str:
        async with httpcore.AsyncConnectionPool(max_keepalive_connections=0, retries=0) as pool:
            resp = await pool.request(
                "GET",
                f"{METADATA_IDENTITY_URL}?audience={audience}",
                headers=[("Metadata-Flavor", "Google")],
                extensions={"timeout": {"connect": 2.0, "read": 3.0, "write": 2.0, "pool": 2.0}},
            )
            if resp.status != 200:
                raise ConnectionError("identity token unavailable")
            return resp.content.decode("ascii").strip()

    return provide


class RemoteFetch:
    def __init__(self, fetcher_url: str, token_provider: TokenProvider, *, post: PostFn | None = None) -> None:
        if urlsplit(fetcher_url).scheme != "https":
            raise ValueError("fetcher の URL は https だけ")
        self._endpoint = fetcher_url.rstrip("/") + FETCH_PATH
        self._token = token_provider
        self._post = post or _httpcore_post

    def _failure(self, request: FetchRequest, why: str) -> FetchResult:
        log_event("fetcher_client.failure", severity="WARNING", why=why)
        return FetchResult(requested_url=request.url[:2048], outcome=FetchOutcome.NETWORK_ERROR)

    async def fetch(self, request: FetchRequest) -> FetchResult:
        try:
            token = await self._token()
            status, raw = await self._post(
                self._endpoint,
                request.model_dump_json().encode("utf-8"),
                {"content-type": "application/json", "authorization": f"Bearer {token}"},
            )
        except Exception as e:  # noqa: BLE001  通信の失敗は想定内（例外を外へ出さない）
            return self._failure(request, type(e).__name__)
        if status != 200:
            return self._failure(request, f"status_{status}")
        if len(raw) > MAX_RESPONSE_BYTES:
            return self._failure(request, "too_large")
        try:
            result = FetchResult.model_validate_json(raw)
        except (ValidationError, json.JSONDecodeError, ValueError):
            return self._failure(request, "bad_result")
        if result.requested_url != request.url[:2048] and result.outcome is not FetchOutcome.BLOCKED:
            return self._failure(request, "url_mismatch")
        return result
