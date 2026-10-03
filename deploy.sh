#!/bin/sh
# claim-audit-agent の Cloud Run デプロイ雛形（設計 §2・§8）。
#
# 既定は DRY_RUN=1（実行する gcloud コマンドを表示するだけ）。実際に出すのは人間が --apply を付けた時だけ。
# このスクリプトは allUsers を付けない（公開は §8 の段階に沿って人間が別途行う）。秘密・鍵・実プロジェクト ID は書かない。
#
#   PROJECT_ID=<id> SA_AGENT=<sa-email> ./deploy.sh agent              # S1 claim-audit-agent（staging・IAM認証）
#   PROJECT_ID=<id> SA_DEMO=<sa-email>  FETCHER_URL=<url> ./deploy.sh demo     # S2 claim-audit-demo（公開用）
#   PROJECT_ID=<id> SA_FETCHER=<sa-email> ALLOWED_PREFIXES=<...> ./deploy.sh fetcher  # S3 claim-audit-fetcher
#
# 任意の環境変数: REGION(既定 asia-northeast1) / PROMPT_VERSION / GEMINI_LOCATION / GEMINI_MODEL /
#   SELF_ORIGIN / SUBMISSION_URL / LP_SEED_URLS / FETCHER_URL / ALLOWED_PREFIXES
set -eu

TARGET="${1:-}"
APPLY=0
[ "${2:-}" = "--apply" ] && APPLY=1
[ "$APPLY" = 1 ] && DRY_RUN=0 || DRY_RUN="${DRY_RUN:-1}"

REGION="${REGION:-asia-northeast1}"
: "${PROJECT_ID:?PROJECT_ID が要ります（実プロジェクト ID はコードに書かない）}"

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '+'
    for a in "$@"; do printf ' %s' "$a"; done
    printf '\n'
  else
    "$@"
  fi
}

PROMPT_VERSION="${PROMPT_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"

# 環境変数は区切り文字を @ にして渡す（値にカンマを含む ALLOWED_PREFIXES 等のため）
env_pair() { [ -n "${2:-}" ] && printf '@%s=%s' "$1" "$2" || true; }

case "$TARGET" in
  agent)
    # S1: 開発・評価・Gate2。IAM 認証のまま。allUsers は絶対に付けない。
    SERVICE=claim-audit-agent
    SA="${SA_AGENT:?SA_AGENT が要ります}"
    ENV_VARS="ROLE=agent@ENV=staging@FETCH_MODE=inproc@LIVE_ENABLED=0@GOOGLE_CLOUD_PROJECT=${PROJECT_ID}@PROMPT_VERSION=${PROMPT_VERSION}"
    ENV_VARS="${ENV_VARS}$(env_pair GEMINI_LOCATION "${GEMINI_LOCATION:-}")$(env_pair GEMINI_MODEL "${GEMINI_MODEL:-}")"
    ENV_VARS="${ENV_VARS}$(env_pair SELF_ORIGIN "${SELF_ORIGIN:-}")$(env_pair SUBMISSION_URL "${SUBMISSION_URL:-}")$(env_pair LP_SEED_URLS "${LP_SEED_URLS:-}")"
    SIZING="--memory=1Gi --cpu=1 --cpu-boost --concurrency=8 --timeout=120 --min-instances=0 --max-instances=2"
    ;;
  demo)
    # S2: 公開用。ライブは LIVE_ENABLED=0 と kill_live=true の二重ラッチで閉じて出す（§8 段階1）。
    SERVICE=claim-audit-demo
    SA="${SA_DEMO:?SA_DEMO が要ります（aiplatform.user と datastore.user のみ・鍵なし）}"
    : "${FETCHER_URL:?FETCHER_URL が要ります（S2 は fetcher 経由でだけ外へ出る）}"
    ENV_VARS="ROLE=agent@ENV=public@FETCH_MODE=remote@LIVE_ENABLED=0@GOOGLE_CLOUD_PROJECT=${PROJECT_ID}@PROMPT_VERSION=${PROMPT_VERSION}@FETCHER_URL=${FETCHER_URL}"
    ENV_VARS="${ENV_VARS}$(env_pair GEMINI_LOCATION "${GEMINI_LOCATION:-}")$(env_pair GEMINI_MODEL "${GEMINI_MODEL:-}")"
    ENV_VARS="${ENV_VARS}$(env_pair SELF_ORIGIN "${SELF_ORIGIN:-}")$(env_pair SUBMISSION_URL "${SUBMISSION_URL:-}")$(env_pair LP_SEED_URLS "${LP_SEED_URLS:-}")"
    SIZING="--memory=1Gi --cpu=1 --cpu-boost --concurrency=6 --timeout=120 --min-instances=0 --max-instances=2"
    ;;
  fetcher)
    # S3: 外向き HTTP の唯一の出口。SA にはロールを一切付けない。invoker は sa-demo と sa-agent のみ。
    SERVICE=claim-audit-fetcher
    SA="${SA_FETCHER:?SA_FETCHER が要ります（ロールを付けない SA）}"
    : "${ALLOWED_PREFIXES:?ALLOWED_PREFIXES が要ります（取得スコープ。S3 自身が再検査する）}"
    ENV_VARS="ROLE=fetcher@ENV=public@ALLOWED_PREFIXES=${ALLOWED_PREFIXES}@PROMPT_VERSION=${PROMPT_VERSION}"
    SIZING="--memory=512Mi --cpu=1 --concurrency=16 --timeout=20 --min-instances=0 --max-instances=2"
    ;;
  *)
    echo "使い方: $0 <agent|demo|fetcher> [--apply]" >&2
    exit 2
    ;;
esac

[ "$DRY_RUN" = 1 ] && echo "# DRY_RUN: 表示だけで実行しません（実行は --apply）"

# 常に --no-allow-unauthenticated。allUsers の付与はこのスクリプトでは行わない。
# shellcheck disable=SC2086  # SIZING は意図して分割する
run gcloud run deploy "$SERVICE" \
  --project="$PROJECT_ID" --region="$REGION" --source=. \
  --service-account="$SA" --no-allow-unauthenticated \
  $SIZING \
  --set-env-vars="^@^${ENV_VARS#@}"

# 旧リビジョンへトラフィックを残さない（公開ゲート ⑯）。結果は目で確認する。
run gcloud run services update-traffic "$SERVICE" --project="$PROJECT_ID" --region="$REGION" --to-latest
run gcloud run services describe "$SERVICE" --project="$PROJECT_ID" --region="$REGION" \
  "--format=table(status.traffic.revisionName,status.traffic.percent,status.traffic.latestRevision)"

case "$TARGET" in
  demo)
    echo "# 公開（allUsers）は §8 の段階1の後に人間が実行する。このスクリプトは行わない。"
    echo "# 10/12 の公開ゲート全緑の後だけ: LIVE_ENABLED=1 と control/state_public.kill_live=false（二重ラッチを両方外す）"
    ;;
  fetcher)
    echo "# invoker は sa-demo と sa-agent だけに付ける（人間が実行）。sa-fetcher にはロールを付けない。"
    ;;
esac
