# 依存OSSのライセンス一覧

このファイルは `python -m tools.third_party_notices --write` が、本番イメージに入る全パッケージ（`requirements.txt` の固定版。推移的な依存も固定してある）を、
インストール済みパッケージのメタデータから作ります。**ライセンスの表記は、メタデータに書かれていた文字列そのままです**
（自分で推測した値ではありません。「Apache 2.0」と「Apache-2.0」のように書き方が違うものも、揃えていません）。
全文と著作権表示は、各パッケージの配布物で確認してください。テスト専用の依存（`requirements-dev.txt`）は、本番イメージに入れないので、ここには載せていません
（README に一覧があります）。

| パッケージ | 版 | ライセンス（メタデータの表記） |
|---|---|---|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| distro | 1.9.0 | Apache License, Version 2.0 |
| fastapi | 0.142.2 | MIT |
| google-api-core | 2.41.0 | Apache 2.0 |
| google-auth | 2.61.0 | Apache 2.0 |
| google-cloud-core | 2.8.0 | Apache 2.0 |
| google-cloud-firestore | 2.34.0 | Apache-2.0 |
| google-genai | 2.27.0 | Apache-2.0 |
| googleapis-common-protos | 1.75.5 | Apache-2.0 |
| grpcio | 1.84.0 | Apache-2.0 |
| grpcio-status | 1.84.0 | Apache-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| opentelemetry-api | 1.45.1 | Apache-2.0 |
| proto-plus | 1.29.0 | Apache 2.0 |
| protobuf | 7.36.2 | 3-Clause BSD License |
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic_core | 2.46.5 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| sniffio | 1.3.1 | MIT OR Apache-2.0 |
| starlette | 1.7.0 | BSD-3-Clause |
| tenacity | 9.1.4 | Apache 2.0 |
| typing_extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| websockets | 16.1.1 | BSD-3-Clause |
