"""`python -m app.web`: 公開面（ROLE=agent・S2）か fetcher（ROLE=fetcher・S3）を起動する。ENV=public では危険な設定で起動しない。"""
import uvicorn

from app.config import Role, assert_startup_safe, load_settings


def main() -> None:  # pragma: no cover - サーバーの起動
    settings = load_settings()
    assert_startup_safe(settings)
    if settings.role is Role.FETCHER:
        from app.net.fetcher_server import create_fetcher_app

        app = create_fetcher_app(settings)
    else:
        from app.web.app import create_app

        app = create_app(settings)
    uvicorn.run(app, host="0.0.0.0", port=settings.port, server_header=False, date_header=False, proxy_headers=True)


if __name__ == "__main__":
    main()
