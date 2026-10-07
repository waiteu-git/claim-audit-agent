"""claim-audit-agent（要項監査エージェント）。

モジュール配置（設計書 §2〜§7 の名前と置き場。「次」は未実装で、入る予定の担当タスク）:

  contracts.py          共有の型（pydantic）。型の追加・変更は契約の担当だけ
  config.py             RUN_CAPS / PRESETS / PRICE_TABLE / FETCH_LIMITS と環境変数の読み込み（読むのはここだけ。main.py は除く）
  errors.py             ErrorCode・AppError・classify()・公開してよいメッセージ
  jsonlog.py            構造化ログ（JSON 1行/イベント）
  textsafe.py           可視テキストの安全判定（U+001E・Cf・制御文字）
  model/                ModelPort・GeminiPort・ScriptedPort・cassette・retry（Vertex を呼ぶのはここだけ。main.py の S1 を除く）
  net/                  SafeFetch（外向き HTTP の唯一の出口）: urlcheck・ipcheck・resolver・backend・decode・safefetch・vectors
  ingest/               sanitize（取得物 → SanitizedDoc）・css_hide・inject_scan
  quotes/               DocIndex・QuoteChecker（引用の逐語照合。「検証済み」の印を発行できるのはここだけ）
  checks/               http_probe・auth_wall・text_length・cloud_run_signature・html_signals・class_screen・registry・leak_scan
                        （contains_terms・autorun は差し込み口だけ＝G3）
  adjudicate.py         判定表（要件×観測 → Verdict。判定を書けるのはこのコードだけ）と、要項間の矛盾（find_contradictions）
  agent/                reader・planner（Planner ループと router）・governor・budget・tools・trace・state・acquire・run・report（第2弾 G2）
  cli.py                ローカル CLI（`python -m app.cli <preset>`）。agent と同じく他から import されない
  quota.py              予約→精算・審査員コード・匿名枠・二重ラッチ・ADMIT ゲート。保存先は StatePort（InMemoryState／state_firestore.py）
  state_firestore.py    StatePort の Firestore 実装（本番。実接続はテストしない）
  egress_guard.py       ASGI の全パス共通上限（1分あたりのリクエスト数・転送量）
  fixtures/             プリセット②③の架空フィクスチャ（site/・site.py・gen.py・expected.json・eval.py）
  web/                  公開面 S2（`python -m app.web`。ROLE=fetcher なら net/fetcher_server の S3）・静的 UI・同梱の REPLAY
  main.py               S1 の疎通確認サービス（既存。/probe は S1 だけ）

import の向き（上が下へ依存してよい。逆向き・循環は tests/test_repo_hygiene.py が止める）:

  textsafe / errors            他の app モジュールに依存しない
  contracts                    errors・textsafe だけ
  config / jsonlog             contracts（jsonlog は errors）
  net / model / quotes         contracts・config・jsonlog・errors・textsafe（互いには依存しない）
  ingest                       net.urlcheck（リンク表のスコープ判定を取得時の検査と同じ定義にするため）・textsafe
  checks                       ingest.sanitize.decode_body（本文の文字コードの読みを1つにするため）・config・errors
  adjudicate                   checks
  quota / egress_guard         config・contracts・jsonlog（state_firestore は quota の型だけ）
  fixtures                     site・gen は contracts・config だけ。eval は agent を組み立てる（入口の扱い）
  agent / cli / main / web     他から import されない（agent・cli・web は上のすべてを使ってよい。web は fixtures・quota を組み立てる）

「同じ事実を2か所で判定しない」: 文字コードは ingest.sanitize.decode_body、スコープ照合は contracts.UrlPrefix.matches と
net.urlcheck.validate_url が唯一の定義（tests/test_integration_consistency.py が割れないことを固定する）。
"""
