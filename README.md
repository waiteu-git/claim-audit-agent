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

## 第2弾 G2（Reader → 検査 → 判定 → 出力の縦1本。オフラインでテスト可能な範囲）

- `app/agent/`: `reader`（ツール無し・構造化出力・引用の再検証）／`governor`・`budget`・`tools`・`trace`（上限・許可リスト・重複検知・停止条件・JSONL）／
  `planner`（手動 function calling の Planner ループと、LLM 無しの決定論 `router`）／`acquire`・`run`・`report`。
- ローカル実行: `python -m app.cli <preset> [--inspect-mode planner|router] [--format json|html] [--out PATH] [--trace PATH]`
  （プリセット ID だけを受ける。取得は SafeFetch、モデルは Vertex の Gemini＝`GOOGLE_CLOUD_PROJECT` が要る。テストはフェイクを注入）。
- 判定（Verdict）を書けるのは `app/adjudicate.py` だけ。`tests/test_agent_run.py` が AST で固定する。

## 開発

- 配置・依存の向きは `app/__init__.py` の docstring が正典（共有の型は `app/contracts.py`、設定と環境変数は `app/config.py`）。
- テスト（完全オフライン。外向き通信は `tests/conftest.py` が遮断する）: `pip install -r requirements-dev.txt && python -m pytest`
  - 単体・敵対（モジュールごと）に加えて、`tests/test_integration_*.py`（実モジュールを通しでつなぐ・別実装の食い違い）と
    `tests/test_repo_hygiene.py`（依存の固定・本番イメージの中身・import の向き・S1 が無傷）がある。
  - `xfail` が4件ある（`tests/test_sanitize_adversarial.py` の既知の残り＝HTML 解析の近似の限界。ブラウザでは隠れる文字が可視に残る最小再現）。
- 依存は版を固定する。本番は `requirements.txt`、テスト専用（pytest・cryptography・idna）は `requirements-dev.txt`。
  本番イメージ（Dockerfile）は `requirements.txt` と `app/` だけを入れる。
- デプロイは 3.13（Dockerfile）。ローカルが 3.14 でも通るだけでは足りないので、`tests/test_py313_safety.py` が注釈の遅延評価依存などを検査する。
- `deploy.sh` は既定で表示だけ（`--apply` で初めて gcloud を呼ぶ）。allUsers は付けない。
- Vertex の実測（手動・最大8回）: `GOOGLE_CLOUD_PROJECT=<id> python -m ops.measure_gemini --yes`。結果は `app/model/gemini.py` の docstring へ書き戻す。
