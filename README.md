# claim-audit-agent

要項・規約・FAQ を読み、要件を「原文引用＋出典＋種別」で構造化し、提出物を実際に検査して証拠つきで合否を返す、読み取り専用のエージェント。
（Agentic AI Hackathon with Google Cloud 提出作品。開発中）

## 現状（Gate1）
Cloud Run 上の最小サービス（`/health`・`/probe`）が Vertex AI の Gemini を呼べる。呼び出し上限とキルスイッチは最初から入れてある。

- 認証: Cloud Run は `--no-allow-unauthenticated`（IAM 認証必須）。API キーは使わず、専用サービスアカウントの `roles/aiplatform.user` のみ。
- 上限: インスタンス数 `--max-instances=2`・同時実行 8・出力トークン `MAX_OUTPUT_TOKENS`・インスタンス単位の毎時呼び出し上限 `MAX_LLM_CALLS_PER_HOUR`。
- 注意: Cloud Run は `/healthz` を予約している（前段が 404 を返す）ため、ヘルスチェックは `/health`。

## 運用コマンド
```bash
# キルスイッチ ON（全モデル呼び出しが 503 になる）／ OFF
gcloud run services update claim-audit-agent --project=<PROJECT> --region=asia-northeast1 --update-env-vars=KILL_SWITCH=1
gcloud run services update claim-audit-agent --project=<PROJECT> --region=asia-northeast1 --remove-env-vars=KILL_SWITCH
```
