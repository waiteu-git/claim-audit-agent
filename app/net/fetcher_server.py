"""fetcher（S3）のサーバー入口。ROLE=fetcher で起動する別サービス（設計 §2）。

  POST /fetch   FetchRequest（JSON）→ FetchResult（JSON）。取得は**この中の** SafeFetch が、この サービスの許可リスト
                （ALLOWED_PREFIXES）でやり直す。S2 から届いた要求のスコープは信用しない（S2 が乗っ取られても、ここの許可リストの外は取れない）。
  GET  /health  {"ok": true}
それ以外のパスは 404。

要項モード（第11弾）: SPEC_FETCH_ENABLED=1 の時だけ、許可リストの外の公開ページを1ページずつ取る規則（contracts.OpenPageScope）を
SafeFetch に足す。S3 は実行の区切りを見られないので、「1実行1ページ」は S2 が守り、S3 はこの規則で通りうる要求（許可リストにも
GitHub の固定ファイルにも当たらない要求）の数と本文の量を、RepoRelayLimiter と同じ形の窓で数えて頭打ちにする（超えたら 429）。

認証: Authorization: Bearer <ID token> を verify_token（注入できる）で確かめる。Cloud Run は --no-allow-unauthenticated で
プラットフォームが ID token の署名と呼び出し元（roles/run.invoker）を検証してから中へ通すので、既定の verify_token は
「Bearer が付いていること」だけを見る（署名の再検証は未実装＝PR の既知の弱点）。テストは拒否する関数を注入して 401 を確かめる。
本文は小さく（8KB まで）・JSON だけ・余計な欄は拒否（extra=forbid）。例外の中身は応答に出さない。
"""
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from app.config import FETCH_LIMITS, FetchLimits, Settings
from app.contracts import GITHUB_RAW_HOST, FetchPort, FetchRequest, OpenPageScope, RepoRawScope
from app.jsonlog import log_event, log_exception

MAX_FETCH_REQUEST_BYTES = 8 * 1024
TokenVerifier = Callable[[str], bool]


def bearer_present(token: str) -> bool:
    """既定の検証: 空でない Bearer があること（署名の検証は Cloud Run の IAM が済ませている前提）。"""
    return bool(token) and len(token) <= 4096


class RepoRelayLimiter:
    """GitHub の固定ファイル取得（contracts.RepoRawScope）の、S3 自身の取りすぎ止め。インスタンスごと・固定窓。

    呼び出し側（github_repo.fetch_repo_files）の件数・合計の上限は、S2 が乗っ取られると効かない。S3 は要求ごとに状態を持たないので、
    規則が有効な時の raw.githubusercontent.com への要求の数と受け取った本文の量を、窓ごとに数えて頭打ちにする。
    限界: インスタンスを増やせば窓も増える（上限は max-instances × この値）。呼び出し元ごとの区別はしない。
    """

    def __init__(
        self,
        limits: FetchLimits,
        *,
        window_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        max_requests: int | None = None,
        max_bytes: int | None = None,
    ) -> None:
        self._max_requests = limits.repo_relay_requests_per_min if max_requests is None else max_requests
        self._max_bytes = limits.repo_relay_bytes_per_min if max_bytes is None else max_bytes
        self._window_s = window_s
        self._clock = clock
        self._start = clock()
        self._requests = 0
        self._bytes = 0

    def _roll(self) -> None:
        now = self._clock()
        if now - self._start >= self._window_s:
            self._start, self._requests, self._bytes = now, 0, 0

    def admit(self) -> bool:
        self._roll()
        if self._requests >= self._max_requests or self._bytes >= self._max_bytes:
            return False
        self._requests += 1
        return True

    def add_bytes(self, n: int) -> None:
        self._bytes += n


def spec_relay_limiter(limits: FetchLimits, *, clock: Callable[[], float] = time.monotonic) -> RepoRelayLimiter:
    """要項モードの公開ページの取りすぎ止め（RepoRelayLimiter と同じ形。数と量は spec_relay_*）。"""
    return RepoRelayLimiter(limits, clock=clock, max_requests=limits.spec_relay_requests_per_min, max_bytes=limits.spec_relay_bytes_per_min)


def _outside_allow_list(url: str, prefixes) -> bool:  # noqa: ANN001
    """許可リストの外か（形が URL として通らないものも外として数える＝数え過ぎの側）。"""
    from app.net.urlcheck import UrlRejected, in_scope, validate_url

    try:
        return not in_scope(validate_url(url), prefixes)
    except UrlRejected:
        return True


def _is_github_raw(url: str) -> bool:
    try:
        return (urlsplit(url).hostname or "").lower() == GITHUB_RAW_HOST
    except ValueError:
        return False


def create_fetcher_app(
    settings: Settings,
    *,
    fetch: FetchPort | None = None,
    verify_token: TokenVerifier = bearer_present,
    limits: FetchLimits = FETCH_LIMITS,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    if fetch is None:
        from app.net.safefetch import SafeFetch

        # 空なら何も取れない（fail-closed）。GITHUB_RAW_ENABLED=1 の時だけ、公開リポジトリの固定ファイルの規則を足す（既定は無効）
        fetch = SafeFetch(
            settings.allowed_prefixes,
            repo_raw=RepoRawScope() if settings.github_raw_enabled else None,
            open_page=OpenPageScope() if settings.spec_fetch_enabled else None,  # 既定は無効（SPEC_FETCH_ENABLED=1 の時だけ）
        )
    app = FastAPI(title="claim-audit-fetcher", docs_url=None, redoc_url=None, openapi_url=None)
    port: FetchPort = fetch
    relay = RepoRelayLimiter(limits, clock=clock) if settings.github_raw_enabled else None  # 無効なら従来どおり（数えない）
    spec_relay = spec_relay_limiter(limits, clock=clock) if settings.spec_fetch_enabled else None

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True}

    @app.post("/fetch")
    async def do_fetch(request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not verify_token(token.strip()):
            return JSONResponse({"ok": False, "code": "UNAUTHENTICATED"}, status_code=401)
        if "application/json" not in request.headers.get("content-type", ""):
            return JSONResponse({"ok": False, "code": "INVALID_INPUT"}, status_code=415)
        body = await request.body()
        if len(body) > MAX_FETCH_REQUEST_BYTES:
            return JSONResponse({"ok": False, "code": "INVALID_INPUT"}, status_code=413)
        try:
            req = FetchRequest.model_validate_json(body)
        except ValidationError:
            return JSONResponse({"ok": False, "code": "INVALID_INPUT"}, status_code=400)
        counted = relay is not None and _is_github_raw(req.url)
        if counted and not relay.admit():
            log_event("fetcher.repo_relay_limited", severity="WARNING")
            return JSONResponse({"ok": False, "code": "RETRYABLE"}, status_code=429)
        spec_counted = (
            spec_relay is not None and not _is_github_raw(req.url) and _outside_allow_list(req.url, settings.allowed_prefixes)
        )
        if spec_counted and not spec_relay.admit():
            log_event("fetcher.spec_relay_limited", severity="WARNING")
            return JSONResponse({"ok": False, "code": "RETRYABLE"}, status_code=429)
        try:
            result = await port.fetch(req)
        except Exception as e:  # noqa: BLE001  SafeFetch は例外を出さない設計。万一の時も中身は出さない
            log_exception("fetcher.unexpected", e)
            return JSONResponse({"ok": False, "code": "INTERNAL"}, status_code=500)
        if counted:
            relay.add_bytes(len(result.body))
        if spec_counted:
            spec_relay.add_bytes(len(result.body))
        log_event("fetcher.fetched", outcome=result.outcome.value, mode=req.mode.value, bytes=len(result.body))
        return Response(result.model_dump_json(), media_type="application/json")

    return app
