"""fetcher（S3）のサーバー入口。ROLE=fetcher で起動する別サービス（設計 §2）。

  POST /fetch   FetchRequest（JSON）→ FetchResult（JSON）。取得は**この中の** SafeFetch が、この サービスの許可リスト
                （ALLOWED_PREFIXES）でやり直す。S2 から届いた要求のスコープは信用しない（S2 が乗っ取られても、ここの許可リストの外は取れない）。
  GET  /health  {"ok": true}
それ以外のパスは 404。

認証: Authorization: Bearer <ID token> を verify_token（注入できる）で確かめる。Cloud Run は --no-allow-unauthenticated で
プラットフォームが ID token の署名と呼び出し元（roles/run.invoker）を検証してから中へ通すので、既定の verify_token は
「Bearer が付いていること」だけを見る（署名の再検証は未実装＝PR の既知の弱点）。テストは拒否する関数を注入して 401 を確かめる。
本文は小さく（8KB まで）・JSON だけ・余計な欄は拒否（extra=forbid）。例外の中身は応答に出さない。
"""
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from app.config import Settings
from app.contracts import FetchPort, FetchRequest, RepoRawScope
from app.jsonlog import log_event, log_exception

MAX_FETCH_REQUEST_BYTES = 8 * 1024
TokenVerifier = Callable[[str], bool]


def bearer_present(token: str) -> bool:
    """既定の検証: 空でない Bearer があること（署名の検証は Cloud Run の IAM が済ませている前提）。"""
    return bool(token) and len(token) <= 4096


def create_fetcher_app(
    settings: Settings,
    *,
    fetch: FetchPort | None = None,
    verify_token: TokenVerifier = bearer_present,
) -> FastAPI:
    if fetch is None:
        from app.net.safefetch import SafeFetch

        # 空なら何も取れない（fail-closed）。GITHUB_RAW_ENABLED=1 の時だけ、公開リポジトリの固定ファイルの規則を足す（既定は無効）
        fetch = SafeFetch(settings.allowed_prefixes, repo_raw=RepoRawScope() if settings.github_raw_enabled else None)
    app = FastAPI(title="claim-audit-fetcher", docs_url=None, redoc_url=None, openapi_url=None)
    port: FetchPort = fetch

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
        try:
            result = await port.fetch(req)
        except Exception as e:  # noqa: BLE001  SafeFetch は例外を出さない設計。万一の時も中身は出さない
            log_exception("fetcher.unexpected", e)
            return JSONResponse({"ok": False, "code": "INTERNAL"}, status_code=500)
        log_event("fetcher.fetched", outcome=result.outcome.value, mode=req.mode.value, bytes=len(result.body))
        return Response(result.model_dump_json(), media_type="application/json")

    return app
