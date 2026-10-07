"""`python -m app.web`: 公開面（ROLE=agent・S2）か fetcher（ROLE=fetcher・S3）を起動する。ENV=public では危険な設定で起動しない。"""
import uvicorn

from app.config import Role, Settings, assert_startup_safe, load_settings
from app.jsonlog import setup_logging


def build_app(settings: Settings):  # noqa: ANN201  FastAPI
    """起動の組み立て。ログ（JSON 1行/イベント・stdout）を先に有効にする。
    10/8: ここで setup_logging を呼んでおらず、公開サービスがアプリのログを1行も出していなかった（ライブ実行の失敗の原因を、
    ログから追えなかった）。Cloud Run は stdout の JSON（severity・message）をそのまま構造化ログとして取り込む。"""
    setup_logging(settings.log_level)
    assert_startup_safe(settings)
    if settings.role is Role.FETCHER:
        from app.net.fetcher_server import create_fetcher_app

        return create_fetcher_app(settings)
    from app.web.app import create_app

    return create_app(settings)


def main() -> None:  # pragma: no cover - サーバーの起動
    settings = load_settings()
    uvicorn.run(build_app(settings), host="0.0.0.0", port=settings.port, server_header=False, date_header=False, proxy_headers=True)


if __name__ == "__main__":
    main()
