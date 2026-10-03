"""設定。RUN_CAPS・PRESETS・PRICE_TABLE と、環境変数の読み込み（環境変数を読むのはここだけ。既存の main.py は除く）。

他のモジュールは `load_settings()` / `get_settings()` の Settings を引数で受け取る。os.environ を直接読まない。
実 URL・プロジェクト ID・サービスアカウントはコードに書かず、環境変数から読む（プレースホルダは *.example.invalid）。

環境変数（既定は fail-closed 側）:
  ROLE(agent|fetcher) ENV(public|staging|dev) FETCH_MODE(inproc|remote) LIVE_ENABLED(1 のみ有効) KILL_SWITCH(1 のみ有効)
  GOOGLE_CLOUD_PROJECT GEMINI_LOCATION(既定 global) GEMINI_MODEL(既定 gemini-3.7-flash) GEMINI_MODEL_READER GEMINI_MODEL_PLANNER
  PROMPT_VERSION SELF_ORIGIN SUBMISSION_URL FETCHER_URL LP_SEED_URLS(カンマ区切り・最大3) LOG_LEVEL
  ALLOWED_PREFIXES（S3 の取得スコープ。`[exact:]host[/path]` のカンマ区切り）
禁止（ENV=public で起動拒否）: GOOGLE_APPLICATION_CREDENTIALS・FAULT_* ・SCRIPTED_*（startup_violations）。
"""
import os
import sys
from collections.abc import Mapping
from datetime import date
from enum import StrEnum
from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.contracts import (
    EnvName,
    HttpsUrl,
    Preset,
    PresetId,
    PresetKind,
    RunCaps,
    UrlPrefix,
)

# ---------------------------------------------------------------------------
# RUN_CAPS（設計 §3。コードで強制する実行ごとの上限）
# ---------------------------------------------------------------------------
RUN_CAPS = RunCaps(
    model_calls_reader=10,
    model_calls_planner=8,
    model_calls_spare=4,  # 合計22
    model_call_timeout_s=25.0,
    model_retries=2,  # 429/5xx のみ
    retry_backoff_s=(1.0, 8.0),
    tokens_in=90_000,
    tokens_out=14_000,  # thinking 含む
    thinking_budget_reader=1_024,
    thinking_budget_planner=512,
    tool_calls=16,  # AUTORUN 分を含む
    fetches_acquire=3,
    fetches_fetch_link=3,
    fetches_probe=2,  # 合計8
    third_party_origins=4,
    requirements_obligatory=64,  # 必須・禁止
    requirements_speculative=8,
    requirements_optional=8,
    requirements_request=8,
    quote_verify_max_chars=160,
    quote_display_max_chars=80,  # §12 の3 で変更可。LP 引用の件数のみ表示への切替は後工程の環境変数
    wall_clock_s=75.0,  # Cloud Run の timeout は 120 秒
    planner_max_turns=8,
    tool_calls_per_requirement=3,
    consecutive_denials_stop=3,  # 拒否3連続で DEGRADED
    reader_total_chars=50_000,
    reader_chunk_chars=6_000,
    reader_chunk_overlap=400,
    reader_max_parallel=3,
)

# 本文サイズの上限（公開面。§2 ADMIT）
MAX_REQUEST_BODY_BYTES = 4_096
PRESET_ID_PATTERN = r"^[a-z][a-z0-9_]{2,31}$"

# ---------------------------------------------------------------------------
# 単価（設計 §6-1。すべて推測）
# ---------------------------------------------------------------------------
class ModelPrice(BaseModel):
    """1M トークンあたりの円。トークン数に掛けるとそのまま micro 円（1e-6 円）になる。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_jpy_per_mtok: int = Field(gt=0)
    output_jpy_per_mtok: int = Field(gt=0)


class PriceTable(BaseModel):
    """単価表。checked_on が None の間は暫定値（公式価格表を人間が確認していない）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    checked_on: str | None  # 公式価格表を確認した日（ISO）。未確認は None
    source: str
    fx_jpy_per_usd: int = 150
    default: ModelPrice
    models: dict[str, ModelPrice] = Field(default_factory=dict)

    @field_validator("checked_on")
    @classmethod
    def _iso(cls, v: str | None) -> str | None:
        if v is not None:
            date.fromisoformat(v)
        return v

    @property
    def provisional(self) -> bool:
        return self.checked_on is None

    def price_for(self, model_id: str) -> ModelPrice:
        return self.models.get(model_id, self.default)

    def cost_micro_jpy(self, model_id: str, tokens_in: int, tokens_out: int) -> int:
        p = self.price_for(model_id)
        return tokens_in * p.input_jpy_per_mtok + tokens_out * p.output_jpy_per_mtok


# 暫定値＝入力 $1/M・出力 $5/M を ¥150/$ で換算。10/3 に公式価格表を確認して checked_on を入れる。
# 公式×1.5 が暫定値を上回るなら RESERVATION_MICRO_JPY（予約額）を上げる。
PRICE_TABLE = PriceTable(
    checked_on=None,
    source="暫定: 設計書 §6-1（入力約$1/M・出力約$5/M を ¥150/$ で換算）。公式価格表は未確認",
    default=ModelPrice(input_jpy_per_mtok=150, output_jpy_per_mtok=750),
)

# 最悪の1実行（入力9万＋出力1.4万）の約¥24 を丸めた予約額 ¥25（§6-1）
RESERVATION_MICRO_JPY = 25_000_000


def worst_case_micro_jpy(caps: RunCaps = RUN_CAPS, prices: PriceTable = PRICE_TABLE, model_id: str = "") -> int:
    """caps の入出力トークン上限を使い切った時の費用（micro 円）。予約額がこれ以上であること。"""
    return prices.cost_micro_jpy(model_id, caps.tokens_in, caps.tokens_out)


# ---------------------------------------------------------------------------
# 公開面の枠・ガード（設計 §6。意味づけは T10 / T14。数値を1か所に置く）
# ---------------------------------------------------------------------------
class PoolPolicy(BaseModel):
    """ライブ実行の枠1種（§6-2）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    runs_per_day: int
    runs_per_hour: int | None
    daily_cap_micro_jpy: int
    total_cap_micro_jpy: int


class QuotaPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    judge: PoolPolicy
    anonymous: PoolPolicy
    anonymous_slot_hours_jst: tuple[int, ...] = (0, 6, 12, 18)  # 各枠に1回
    anonymous_runs_per_day_after_total: int = 1  # 累計到達後は1回/日に絞って継続
    reservation_ttl_s: int = 130  # 開始+130秒で期限切れ予約を掃除
    admit_gate_per_s: int = 1  # ADMIT 前段のインスタンス内ゲート
    judge_lock_failures_per_hour: int = 5
    live_concurrency_per_instance: int = 2


QUOTA_POLICY = QuotaPolicy(
    judge=PoolPolicy(
        runs_per_day=10, runs_per_hour=3, daily_cap_micro_jpy=250_000_000, total_cap_micro_jpy=3_000_000_000
    ),
    anonymous=PoolPolicy(
        runs_per_day=4, runs_per_hour=None, daily_cap_micro_jpy=100_000_000, total_cap_micro_jpy=1_500_000_000
    ),
)


class GuardLimits(BaseModel):
    """egress_guard・キルスイッチ・SSE の数値（§6-3・§6-6・§8）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    egress_bytes_per_min: int = 2 * 1024 * 1024
    requests_per_min: int = 600
    kill_cache_s: float = 5.0
    sse_send_timeout_s: float = 10.0
    sse_heartbeat_s: float = 10.0


GUARD_LIMITS = GuardLimits()


class FetchLimits(BaseModel):
    """SafeFetch の数値（§5-3・§4 http_probe）。T3 が使い、T9（http_probe）も読む。1か所に置く。

    本文の上限（デコード後 1MiB・probe 先頭 64KB）・転送3ホップ・URL 2048字は契約側の定数
    （contracts.FETCH_BODY_MAX_BYTES / PROBE_BODY_MAX_BYTES / MAX_REDIRECT_HOPS）と同じ値を持ち、テストで一致を固定する。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    connect_timeout_s: float = 3.0
    total_timeout_s: float = 8.0  # 1回の取得（転送を含む全体）
    sock_read_timeout_s: float = 4.0
    max_content_length: int = 3 * 1024 * 1024  # Content-Length がこれを超えたら本文を読む前に拒否（FetchLimit.CONTENT_LENGTH）
    max_decoded_bytes: int = 1024 * 1024  # デコード後。超過は打切り（gzip 爆弾対策）
    probe_prefix_bytes: int = 64 * 1024  # http_probe は本文先頭だけ
    max_redirects: int = 3
    max_url_length: int = 2048
    user_agent: str = "claim-audit-agent/1 (hackathon demo; read-only)"
    accept_encoding: str = "gzip, deflate"
    probe_retry_delay_s: float = 2.0  # TRANSIENT（タイムアウト・接続失敗・429/503）の後、2秒待って
    probe_retry_max: int = 1  # 1回だけ再試行（S-04）。再試行を fetches_probe に数えるかは設計に記載なし（未裁定）


FETCH_LIMITS = FetchLimits()

# ---------------------------------------------------------------------------
# 環境変数 → Settings
# ---------------------------------------------------------------------------
class Role(StrEnum):
    AGENT = "agent"
    FETCHER = "fetcher"


class FetchBackend(StrEnum):
    INPROC = "inproc"  # S1: SafeFetch をプロセス内で使う（開発・Gate2）
    REMOTE = "remote"  # S2: fetcher（S3）へ ID token で


DEFAULT_GEMINI_MODEL = "gemini-3.7-flash"
DEFAULT_GEMINI_LOCATION = "global"
_FORBIDDEN_ENV_PREFIXES = ("FAULT_", "SCRIPTED_")  # 故障注入・台本は staging 専用（§8 ⑩）


def _bool(v: str | None) -> bool:
    return (v or "").strip() == "1"


def _csv(v: str | None) -> tuple[str, ...]:
    return tuple(x.strip() for x in (v or "").split(",") if x.strip())


def parse_prefixes(raw: str | None) -> tuple[UrlPrefix, ...]:
    """ALLOWED_PREFIXES（S3 の環境変数）を解釈する。書式: `[exact:]host[/path]` のカンマ区切り。

    例: `exact:lp.example.invalid/event,svc.example.invalid/fx/`
    """
    out: list[UrlPrefix] = []
    for item in _csv(raw):
        exact = item.startswith("exact:")
        body = item.removeprefix("exact:")
        host, sep, rest = body.partition("/")
        out.append(UrlPrefix(host=host, path_prefix="/" + rest if sep else "/", exact=exact))
    return tuple(out)


class Settings(BaseModel):
    """環境変数から作る実行設定。デフォルトは fail-closed 側（ライブ無効・開発環境）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Role = Role.AGENT
    env: EnvName = EnvName.DEV
    fetch_backend: FetchBackend = FetchBackend.INPROC
    google_cloud_project: str | None = None  # 値はコードへ書かない。Vertex 呼び出しの時だけ必須
    gemini_location: str = DEFAULT_GEMINI_LOCATION
    gemini_model_reader: str = DEFAULT_GEMINI_MODEL
    gemini_model_planner: str = DEFAULT_GEMINI_MODEL
    prompt_version: str = "dev"
    kill_switch: bool = False  # L2: KILL_SWITCH=1 で全モデル呼び出しを止める
    live_enabled: bool = False  # §8 二重ラッチの片方。既定は閉
    self_origin: HttpsUrl | None = None
    submission_url: HttpsUrl | None = None
    fetcher_url: HttpsUrl | None = None
    allowed_prefixes: tuple[UrlPrefix, ...] = ()
    lp_seed_urls: tuple[HttpsUrl, ...] = Field(default=(), max_length=3)
    log_level: str = "INFO"

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "Settings":
        e = environ
        default_model = e.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
        return cls(
            role=Role(e.get("ROLE", Role.AGENT.value)),
            env=EnvName(e.get("ENV", EnvName.DEV.value)),
            fetch_backend=FetchBackend(e.get("FETCH_MODE", FetchBackend.INPROC.value)),
            google_cloud_project=e.get("GOOGLE_CLOUD_PROJECT") or None,
            gemini_location=e.get("GEMINI_LOCATION") or DEFAULT_GEMINI_LOCATION,
            gemini_model_reader=e.get("GEMINI_MODEL_READER") or default_model,
            gemini_model_planner=e.get("GEMINI_MODEL_PLANNER") or default_model,
            prompt_version=e.get("PROMPT_VERSION") or "dev",
            kill_switch=_bool(e.get("KILL_SWITCH")),
            live_enabled=_bool(e.get("LIVE_ENABLED")),
            self_origin=e.get("SELF_ORIGIN") or None,
            submission_url=e.get("SUBMISSION_URL") or None,
            fetcher_url=e.get("FETCHER_URL") or None,
            allowed_prefixes=parse_prefixes(e.get("ALLOWED_PREFIXES")),
            lp_seed_urls=_csv(e.get("LP_SEED_URLS")),
            log_level=(e.get("LOG_LEVEL") or "INFO").upper(),
        )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """環境変数を読む唯一の入口。environ を渡せばテストで os.environ に触らずに済む。"""
    return Settings.from_environ(os.environ if environ is None else environ)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


# ---------------------------------------------------------------------------
# プリセット（設計 §2・§6-2）。公開面の入力はこの ID だけ（閉世界）
# ---------------------------------------------------------------------------
PRESET_LP_SELF: PresetId = "lp_self"  # ① 本ハッカソンの募集ページと本サービス自身を自己監査
PRESET_SAMPLE_DEFECT: PresetId = "sample_defect"  # ② 欠陥入りの架空サンプル
PRESET_SAMPLE_INJECTION: PresetId = "sample_injection"  # ③ 偽の命令入りの架空サンプル
PRESET_IDS: tuple[PresetId, ...] = (PRESET_LP_SELF, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION)

# 実 URL はデプロイ時の環境変数で与える。無い時に使うプレースホルダ（実在しない TLD）。
PLACEHOLDER_LP = "https://lp.example.invalid"
PLACEHOLDER_SELF = "https://self.example.invalid"

# ②③のフィクスチャの配信パス（T12 が実体を置く。ここは合意の置き場所＝後工程で合わせる）
FIXTURE_DEFECT_PREFIX = "/fx/defect/"
FIXTURE_INJECTION_PREFIX = "/fx/inject/"


def _host_path(url: str) -> tuple[str, str]:
    p = urlsplit(url)
    return (p.hostname or "").lower(), p.path or "/"


def build_presets(settings: Settings | None = None) -> dict[PresetId, Preset]:
    """Settings からプリセット3種を組み立てる。LP の実 URL（最大3）は LP_SEED_URLS、自サービスは SELF_ORIGIN。"""
    s = settings or Settings()
    self_origin = (s.self_origin or PLACEHOLDER_SELF).rstrip("/")
    self_host, _ = _host_path(self_origin + "/")

    lp_seeds = s.lp_seed_urls or (f"{PLACEHOLDER_LP}/event", f"{PLACEHOLDER_LP}/faq")
    lp_prefixes: list[UrlPrefix] = []
    for u in lp_seeds:
        host, path = _host_path(u)
        lp_prefixes.append(UrlPrefix(host=host, path_prefix=path, exact=True))  # 正確な URL だけ（zenn.dev 全体は開けない）
    # 自サービスは "/" の完全一致と /fx/ 配下だけ。/api/ は拒否（自己再帰・増幅の防止）
    self_prefixes = [
        UrlPrefix(host=self_host, path_prefix="/", exact=True),
        UrlPrefix(host=self_host, path_prefix="/fx/"),
    ]
    submission = s.submission_url or f"{self_origin}/"

    return {
        PRESET_LP_SELF: Preset(
            preset_id=PRESET_LP_SELF,
            label_ja="本ハッカソンの募集ページと本サービス自身を自己監査",
            kind=PresetKind.LIVE_LP,
            spec_seed_urls=tuple(lp_seeds),
            submission_url=submission,
            allowed_prefixes=(*lp_prefixes, *self_prefixes),
        ),
        PRESET_SAMPLE_DEFECT: Preset(
            preset_id=PRESET_SAMPLE_DEFECT,
            label_ja="欠陥入りの架空サンプル",
            kind=PresetKind.FIXTURE_DEFECT,
            spec_seed_urls=(f"{self_origin}{FIXTURE_DEFECT_PREFIX}spec/",),
            submission_url=f"{self_origin}{FIXTURE_DEFECT_PREFIX}submission/",
            allowed_prefixes=(UrlPrefix(host=self_host, path_prefix=FIXTURE_DEFECT_PREFIX),),
        ),
        PRESET_SAMPLE_INJECTION: Preset(
            preset_id=PRESET_SAMPLE_INJECTION,
            label_ja="偽の命令入りの架空サンプル",
            kind=PresetKind.FIXTURE_INJECTION,
            spec_seed_urls=(f"{self_origin}{FIXTURE_INJECTION_PREFIX}spec/",),
            submission_url=f"{self_origin}{FIXTURE_INJECTION_PREFIX}submission/",
            allowed_prefixes=(UrlPrefix(host=self_host, path_prefix=FIXTURE_INJECTION_PREFIX),),
        ),
    }


# 既定（プレースホルダ URL）。実 URL が要る処理は build_presets(get_settings()) を使う。
PRESETS: dict[PresetId, Preset] = build_presets()


# ---------------------------------------------------------------------------
# 起動時アサーション（設計 §8 公開ゲート ⑩）
# ---------------------------------------------------------------------------
class StartupError(RuntimeError):
    """公開環境として危険な設定で起動しようとした。起動を拒否する。"""


def startup_violations(
    settings: Settings,
    environ: Mapping[str, str] | None = None,
    loaded_modules: Mapping[str, object] | None = None,
) -> list[str]:
    """ENV=public で守るべき条件の違反を返す（空なら安全）。ENV=public 以外は検査しない。"""
    if settings.env is not EnvName.PUBLIC:
        return []
    env = os.environ if environ is None else environ
    mods = sys.modules if loaded_modules is None else loaded_modules
    out: list[str] = []
    if settings.fetch_backend is not FetchBackend.REMOTE:
        out.append("ENV=public では FETCH_MODE=remote が必須")
    if env.get("GOOGLE_APPLICATION_CREDENTIALS"):
        out.append("GOOGLE_APPLICATION_CREDENTIALS が設定されています（鍵ファイルを持たせない）")
    bad = sorted(k for k in env if k.startswith(_FORBIDDEN_ENV_PREFIXES))
    if bad:
        out.append(f"故障注入・台本用の環境変数があります: {', '.join(bad)}")
    if "app.model.scripted" in mods:
        out.append("ScriptedPort が import されています（テスト専用）")
    return out


def assert_startup_safe(
    settings: Settings,
    environ: Mapping[str, str] | None = None,
    loaded_modules: Mapping[str, object] | None = None,
) -> None:
    violations = startup_violations(settings, environ, loaded_modules)
    if violations:
        raise StartupError("; ".join(violations))
