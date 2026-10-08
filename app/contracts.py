"""共有契約（pydantic v2）。他モジュールが共有する型はすべてここに置く。型の追加・変更は T1 の担当だけが行う。

設計書の用語に合わせる（§3 判定表・§4 ツール表・§5 引用検証・§7 TraceEvent）。
信頼境界の規則を型で表している:
  - LLM 出力型（RawRequirement / ReaderOutput）は verified/locator を持てない。extra=forbid。
  - VerifiedRequirement は VerificationSeal（DocIndex だけが発行）無しには作れず、REPORT のシリアライザはそれしか受けない。
  - Planner が見る StateView と、外へ出る TraceEvent は自由文のフィールドを持たない（enum・ID・数値・短い識別子のみ）。
  - 画面・トレースへ出る文字列は、ゼロ幅・bidi・タグ文字・制御文字を含められない（textsafe）。

後続モジュール（T3 SafeFetch・T4 サニタイザ・T5 引用検証器・T9 検査と判定）がこれらの型をどう組み立てるかの
通しの例は tests/test_contract_audit.py（デモ② D1・D2・D4 を契約の型だけで通すテスト）。
契約の取り決め（リダイレクトの表し方・SENTENCE_TOO_LONG の span・QuoteStep の escape・scope 照合 UrlPrefix.matches 等）は
各型の docstring に書いてある。
"""
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from app.errors import AppError, ErrorCode
from app.textsafe import BLOCK_SEP, INJECTION_PLACEHOLDER, is_safe_text  # noqa: F401  BLOCK_SEP・INJECTION_PLACEHOLDER は再エクスポート

# ---------------------------------------------------------------------------
# 定数（設計の固定値。config.RUN_CAPS と一致することを tests が検査する）
# ---------------------------------------------------------------------------
QUOTE_SPAN_MAX_CHARS = 160  # 内部検証の引用上限（§3）。画面表示は config 側の 80 字
REASON_MAX_CHARS = 140  # モデルの自由文が許されるのは reason だけ（§3）
MAX_EVENTS_PER_RUN = 400  # Firestore へ保存するイベント数（§7）
MAX_EVENT_BYTES = 600  # 1イベントの目安上限（§7。state_view だけ例外）
FETCH_BODY_MAX_BYTES = 1024 * 1024  # デコード後 1MiB で打切り（§5-3）
PROBE_BODY_MAX_BYTES = 64 * 1024  # http_probe は本文先頭 64KB（§4）
MAX_REDIRECT_HOPS = 3  # 手動リダイレクト最大3ホップ（§5-3）
STATE_VIEW_TARGET_BYTES = 3 * 1024  # StateView は約3KB（§2）。超過は T8 が間引く

# 応答ヘッダの許可リスト（§4 http_probe）。これ以外は FetchResult に載せられない。
ALLOWED_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "content-encoding",
        "server",
        "via",
        "location",
        "www-authenticate",
        "retry-after",
        "cache-control",
        "x-audit-app",
        "x-cloud-trace-context",
    }
)


# ---------------------------------------------------------------------------
# 基底と制約つきの型
# ---------------------------------------------------------------------------
class _Strict(BaseModel):
    """未知フィールドを拒否する基底（設計 §5-2 層4: extra=forbid）。"""

    model_config = ConfigDict(
        extra="forbid",
        protected_namespaces=(),  # model_id などのフィールド名を許す
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )


class _Frozen(_Strict):
    """生成後に変更できない契約型の基底。"""

    model_config = ConfigDict(frozen=True)


def _display_safe(v: str) -> str:
    if not is_safe_text(v, allow_block_sep=False):
        raise ValueError("ゼロ幅・bidi・タグ文字・制御文字・ブロック境界は含められません")
    return v


def _text_safe(v: str) -> str:
    if not is_safe_text(v, allow_block_sep=True):
        raise ValueError("ゼロ幅・bidi・タグ文字・制御文字は含められません")
    return v


DocId = Annotated[str, StringConstraints(pattern=r"^D[0-9]{1,3}$")]
LinkId = Annotated[str, StringConstraints(pattern=r"^L[0-9]{1,3}$")]
ReqId = Annotated[str, StringConstraints(pattern=r"^R[0-9]{1,3}$")]
ObsId = Annotated[str, StringConstraints(pattern=r"^O[0-9]{1,3}$")]
RunId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")]  # secrets.token_urlsafe(16)
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{8,64}$")]  # sha256 の先頭8〜64字
# 識別子風の短い語。自由文を入れさせないために、記号は . : _ - だけ。
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:\-]{1,64}$")]
PresetId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,31}$")]
RouteId = Token
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[^\s\\@]+$", max_length=2048)]


# 画面・トレースに出る文字列（textContent で描く）。長さ上限と安全文字の両方を課す。
Display40 = Annotated[str, StringConstraints(max_length=40), AfterValidator(_display_safe)]
Display60 = Annotated[str, StringConstraints(max_length=60), AfterValidator(_display_safe)]
Display80 = Annotated[str, StringConstraints(max_length=80), AfterValidator(_display_safe)]
Display160 = Annotated[str, StringConstraints(max_length=QUOTE_SPAN_MAX_CHARS), AfterValidator(_display_safe)]
Display200 = Annotated[str, StringConstraints(max_length=200), AfterValidator(_display_safe)]
Reason140 = Annotated[str, StringConstraints(max_length=REASON_MAX_CHARS), AfterValidator(_display_safe)]


# ---------------------------------------------------------------------------
# 列挙
# ---------------------------------------------------------------------------
class Kind(StrEnum):
    """要件の種別（§5-1）。値は設計書・画面のバッジと同じ日本語。"""

    REQUIRED = "必須"
    PROHIBITED = "禁止"
    OPTIONAL = "任意"
    REQUEST = "依頼"  # お願い・推奨などの依頼文言
    SPECULATIVE = "推測"  # 原文引用なし・モデルの推論


OBLIGATORY_KINDS = frozenset({Kind.REQUIRED, Kind.PROHIBITED})  # 最大64件の枠（§3）


class CheckClass(StrEnum):
    """検査できる要件クラスは6つだけ（§3）。それ以外は NONE＝確認不能に倒す。"""

    LENGTH_LIMIT = "length_limit"  # text_length
    AUTH_WALL = "auth_wall"  # http_probe
    LEAK = "leak"  # leak_scan
    RUNTIME_SIGNATURE = "runtime_signature"  # cloud_run_signature
    GUIDANCE_PRESENT = "guidance_present"  # contains_terms（テストアカウント案内など）
    URL_PRESENT = "url_present"  # contains_terms（動画URLなど）
    NONE = "none"


class Checker(StrEnum):
    """run_check の checker（§4）。"""

    TEXT_LENGTH = "text_length"
    CONTAINS_TERMS = "contains_terms"
    LEAK_SCAN = "leak_scan"
    AUTH_WALL = "auth_wall"
    CLOUD_RUN_SIGNATURE = "cloud_run_signature"


# 要件クラス → それを検査する checker（§3「検査できる要件クラスは6つだけ」・§4 run_check）。
# auth_wall は http_probe の観測を auth_wall チェッカーが保存済みの観測から読む。NONE は検査できない＝確認不能に倒す。
CHECK_CLASS_CHECKER: dict[CheckClass, Checker | None] = {
    CheckClass.LENGTH_LIMIT: Checker.TEXT_LENGTH,
    CheckClass.AUTH_WALL: Checker.AUTH_WALL,
    CheckClass.LEAK: Checker.LEAK_SCAN,
    CheckClass.RUNTIME_SIGNATURE: Checker.CLOUD_RUN_SIGNATURE,
    CheckClass.GUIDANCE_PRESENT: Checker.CONTAINS_TERMS,
    CheckClass.URL_PRESENT: Checker.CONTAINS_TERMS,
    CheckClass.NONE: None,
}


class ToolName(StrEnum):
    """Planner が呼べる5本だけ（§4）。"""

    FETCH_LINK = "fetch_link"
    HTTP_PROBE = "http_probe"
    RUN_CHECK = "run_check"
    MARK_UNVERIFIABLE = "mark_unverifiable"
    FINISH = "finish"


class Slot(StrEnum):
    """矛盾判定用の固定語彙（§5-1。15語以内）。Reader が付け、矛盾はコードが決める。"""

    NONE = "なし"
    DEADLINE = "締切"
    CHAR_LIMIT = "文字数"
    VIDEO_LENGTH = "動画尺"
    REVIEW_FORMAT = "審査形態"
    SUBMIT_TO = "提出先"
    VISIBILITY = "公開範囲"
    URL = "URL"
    ELIGIBILITY = "参加資格"
    TEAM_SIZE = "チーム人数"
    REQUIRED_TECH = "必須技術"
    LICENSE = "ライセンス"
    PRIZE = "賞"
    SUBMISSION_FORMAT = "提出形式"
    LANGUAGE = "言語"


class PageClass(StrEnum):
    """ページ種別（Reader が提案し、検査を減らす方向はコードが裏取りする。§3 AUTORUN）。"""

    CONTENT = "content"
    LOGIN_WALL = "login_wall"
    ERROR_PAGE = "error_page"
    EMPTY = "empty"
    SPA_SHELL = "spa_shell"


class LinkRole(StrEnum):
    """リンクの役割。Reader が提案し、検査を減らす方向（login）はコードが hrefのパス規則で裏取りする。"""

    DOCS = "docs"
    DEMO = "demo"
    TERMS = "terms"
    LOGIN = "login"
    OTHER = "other"


class DocRole(StrEnum):
    """spec＝要項・LP・FAQ（要件の置き場）／submission＝検査される提出物（§5-2）。"""

    SPEC = "spec"
    SUBMISSION = "submission"


class VerdictLabel(StrEnum):
    """判定表（§3）。モデルは判定を書けず、adjudicate.py だけが出す。矛盾は Contradiction として別集計。"""

    PASS = "適合"  # 機械検証（OBS強の合格）
    PRESUMED_PASS = "推定適合"  # 提出物の自己申告・未検証
    FAIL = "不適合"
    UNVERIFIABLE = "確認不能"
    REFERENCE = "参考"  # 推測 kind。集計外


class UnverifiableReason(StrEnum):
    """確認不能の理由コード（§3）。"""

    NO_EVIDENCE = "NO_EVIDENCE"
    BUDGET = "BUDGET"
    TRUNCATED = "TRUNCATED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NEEDS_JS = "NEEDS_JS"
    NEEDS_AUTH = "NEEDS_AUTH"
    NOT_PUBLIC = "NOT_PUBLIC"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    FUTURE = "FUTURE"
    HUMAN_ONLY = "HUMAN_ONLY"
    TRANSIENT = "TRANSIENT"
    FETCH_BLOCKED = "FETCH_BLOCKED"


# 画面に出す理由コードの日本語（T11 が使う）
REASON_LABEL_JA: dict[UnverifiableReason, str] = {
    UnverifiableReason.NO_EVIDENCE: "判断できる根拠が見つかりません",
    UnverifiableReason.BUDGET: "実行の上限に達したため検査していません",
    UnverifiableReason.TRUNCATED: "文書が長く、読み切れていません",
    UnverifiableReason.OUT_OF_SCOPE: "検査できる範囲の外です",
    UnverifiableReason.NEEDS_JS: "JavaScript の描画が必要で、検査できません",
    UnverifiableReason.NEEDS_AUTH: "ログインが必要で、検査できません",
    UnverifiableReason.NOT_PUBLIC: "非公開の情報のため、検査できません",
    UnverifiableReason.UNSUPPORTED_TYPE: "対応していない形式です",
    UnverifiableReason.FUTURE: "将来の時点の事項で、今は検査できません",
    UnverifiableReason.HUMAN_ONLY: "人の判断が必要です",
    UnverifiableReason.TRANSIENT: "一時的に取得できませんでした",
    UnverifiableReason.FETCH_BLOCKED: "取得が許可されていません",
}


class QuoteRejectReason(StrEnum):
    """引用検証 Rejected の理由コード（§5-1）。"""

    EMPTY = "empty"
    NOT_FOUND = "not_found"  # 言い換え・省略・他文書のみ・隠しテキスト内
    TOO_SHORT = "too_short"  # 正規化後6字未満
    SHORT_NOT_ALLOWED = "short_not_allowed"  # 6〜11字で出現が複数、または必須・任意・数値語を含まない
    TOO_LONG = "too_long"  # 160字超
    ELIDED = "elided"  # 「…」「...」を含む
    AMBIGUOUS = "ambiguous"  # 同一文書で4回以上出現
    CROSSES_BLOCK = "crosses_block"  # ブロック境界（表のセル等）をまたぐ
    INJECTION_OVERLAP = "injection_overlap"  # 注入疑い区間と重なる（P-INJ-01）


class DemotionReason(StrEnum):
    """モデルが申告した kind と最終 kind が違う理由（§5-1）。

    span（VerifiedSpan）は QUOTE_UNVERIFIED のときだけ無く、他の降格では必ず持つ。
    SENTENCE_TOO_LONG（拡張後の文が160字超）では拡張前の検証済み区間（160字以内）を span に載せる
    （original_span は160字までなので、拡張後の文は載せられない）。
    """

    QUOTE_UNVERIFIED = "quote_unverified"  # 再引用でも逐語一致せず → 推測（引用なし）
    NO_OBLIGATION_WORD = "no_obligation_word"  # 必須と言うが義務語が無い → 推測
    NEGATION_OR_EXCEPTION = "negation_or_exception"  # 否定・例外語が文にあるが引用に無い → 推測
    SENTENCE_TOO_LONG = "sentence_too_long"  # 拡張後の文が160字超 → 推測
    REQUEST_WORDING = "request_wording"  # 依頼語彙のみ → 任意


# 降格理由 → 最終 kind（§5-1）
DEMOTION_RESULT_KIND: dict[DemotionReason, Kind] = {
    DemotionReason.QUOTE_UNVERIFIED: Kind.SPECULATIVE,
    DemotionReason.NO_OBLIGATION_WORD: Kind.SPECULATIVE,
    DemotionReason.NEGATION_OR_EXCEPTION: Kind.SPECULATIVE,
    DemotionReason.SENTENCE_TOO_LONG: Kind.SPECULATIVE,
    DemotionReason.REQUEST_WORDING: Kind.OPTIONAL,
}


class Chip(StrEnum):
    """要件行に付けるチップ（§5-1）。"""

    NEGATION_OR_EXCEPTION = "negation_or_exception"
    REQUEST_WORDING = "request_wording"


CHIP_LABEL_JA: dict[Chip, str] = {
    Chip.NEGATION_OR_EXCEPTION: "否定・例外を含む文",
    Chip.REQUEST_WORDING: "依頼文言（違反時の扱い不明）",
}


class Phase(StrEnum):
    """状態遷移（§3）。DEGRADED / ABORTED / REPLAY は例外終端。"""

    ADMIT = "ADMIT"
    ACQUIRE = "ACQUIRE"
    READ = "READ"
    AUTORUN = "AUTORUN"
    INSPECT = "INSPECT"
    ADJUDICATE = "ADJUDICATE"
    REPORT = "REPORT"
    PERSIST = "PERSIST"
    DONE = "DONE"
    DEGRADED = "DEGRADED"
    ABORTED = "ABORTED"
    REPLAY = "REPLAY"


class RunStatus(StrEnum):
    """実行の終わり方。REPLAY は mode で表す（保存済みの再生は元の status を持つ）。"""

    DONE = "DONE"
    DEGRADED = "DEGRADED"
    ABORTED = "ABORTED"


class DegradedReason(StrEnum):
    """DEGRADED（部分結果を返す終端）の理由（§3）。未検査の要件は理由コードつきの確認不能で必ず出す。"""

    BUDGET = "BUDGET"  # 予算（呼び出し・トークン・取得・ツール）切れ
    MODEL_FAILURE = "MODEL_FAILURE"  # Vertex 失敗（最初の成功の後）
    DENIAL_STREAK = "DENIAL_STREAK"  # Governor の拒否が連続（RunCaps.consecutive_denials_stop）


class AbortReason(StrEnum):
    """ABORTED（予約を精算して打ち切る終端）の理由（§3）。"""

    KILL = "KILL"  # キルスイッチ
    CLIENT_DISCONNECT = "CLIENT_DISCONNECT"  # クライアント切断
    WALL_CLOCK = "WALL_CLOCK"  # 壁時計の上限（RUN_CAPS.wall_clock_s）超過


class RunMode(StrEnum):
    """LIVE=この実行、REPLAY=保存済みの実行の再生（§6-4）。"""

    LIVE = "LIVE"
    REPLAY = "REPLAY"


class EnvName(StrEnum):
    """ENV 名前空間（§6-6）。公開枠と開発の実行を混ぜないための分離。"""

    PUBLIC = "public"
    STAGING = "staging"
    DEV = "dev"


class Actor(StrEnum):
    """イベントを出した主体（§7）。コード側の検証・判定も actor として区別する。"""

    GOVERNOR = "governor"
    READER = "reader"
    PLANNER = "planner"
    TOOL = "tool"
    ADJUDICATOR = "adjudicator"
    VERIFIER = "verifier"


class TraceType(StrEnum):
    """TraceEvent の種別（§7）。"""

    PHASE_ENTER = "phase_enter"
    MODEL_CALL = "model_call"
    STATE_VIEW = "state_view"
    TOOL_REQUEST = "tool_request"
    POLICY_DECISION = "policy_decision"
    TOOL_RESULT = "tool_result"
    QUOTE_CHECK = "quote_check"
    INJECTION_SIGNAL = "injection_signal"
    REPLAN = "replan"
    AUTORUN = "autorun"
    VERDICT = "verdict"
    BUDGET_SNAPSHOT = "budget_snapshot"
    ABORT = "abort"


class Decision(StrEnum):
    """Governor の許可／拒否。"""

    ALLOW = "allow"
    DENY = "deny"


class PolicyId(StrEnum):
    """Governor の policy_id 一覧（§4）。拒否は必ず policy_id と理由コードを出す。"""

    SCOPE = "P-SCOPE-01"
    LINK = "P-LINK-01"
    SSRF_IP = "P-SSRF-IP-01"
    BUDGET_CALLS = "P-BUDGET-CALLS-01"
    BUDGET_TOKENS = "P-BUDGET-TOKENS-01"
    DUP = "P-DUP-01"
    PHASE = "P-PHASE-02"
    INJ = "P-INJ-01"
    KILL = "P-KILL-01"
    UNVERIF = "P-UNVERIF-01"
    MINTURN = "P-MINTURN-01"


class DenialCode(StrEnum):
    """Governor の拒否の理由コード（TraceEvent.reason_code と同じ語）。StateView.last_denial に「直前の拒否」として載る。

    Planner は拒否の理由を見て別の手に移る（同じ呼び出しを繰り返すと P-DUP-01 の REPEATED_DENIAL で即座に拒否され、
    拒否の連続が RunCaps.consecutive_denials_stop に達すると DEGRADED になる）。
    """

    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    BAD_ARGS = "BAD_ARGS"
    TOOL_CAP = "TOOL_CAP"
    OPEN_REQUIREMENTS = "OPEN_REQUIREMENTS"
    UNKNOWN_LINK = "UNKNOWN_LINK"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    LOGIN_LINK = "LOGIN_LINK"
    NO_SUBMISSION_URL = "NO_SUBMISSION_URL"
    FETCH_CAP = "FETCH_CAP"
    ORIGIN_CAP = "ORIGIN_CAP"
    UNKNOWN_REQ = "UNKNOWN_REQ"
    NOT_CHECKABLE = "NOT_CHECKABLE"
    PROBE_FIRST = "PROBE_FIRST"  # auth_wall・cloud_run_signature は、先に http_probe の観測が要る
    CLASS_MISMATCH = "CLASS_MISMATCH"
    REQ_CAP = "REQ_CAP"
    SPECULATIVE = "SPECULATIVE"
    CODE_ONLY = "CODE_ONLY"
    ALREADY_DECIDED = "ALREADY_DECIDED"
    CHECK_FIRST = "CHECK_FIRST"
    NO_PREMISE = "NO_PREMISE"
    DUPLICATE_CALL = "DUPLICATE_CALL"
    REPEATED_DENIAL = "REPEATED_DENIAL"  # 拒否された呼び出しを、状態が変わらないまま繰り返した
    NO_CALL = "NO_CALL"


class ModelPurpose(StrEnum):
    """モデルの役割は2つだけ（§2）。Reader=ツール無し・スキーマ強制、Planner=関数呼び出しのみ。"""

    READER = "reader"
    PLANNER = "planner"


class ObsCode(StrEnum):
    """検査の観測を1語にしたコード。Planner の次の StateView に「直前の観測コード」として載る。"""

    OK = "OK"
    AUTH_WALL = "AUTH_WALL"
    NO_AUTH_WALL = "NO_AUTH_WALL"
    SPA_SHELL = "SPA_SHELL"
    TRANSIENT = "TRANSIENT"
    WITHIN_LIMIT = "WITHIN_LIMIT"
    OVER_LIMIT = "OVER_LIMIT"
    LIMIT_UNDECIDABLE = "LIMIT_UNDECIDABLE"  # 空白除去あり／なしの片方だけ超過（§3）
    TERMS_FOUND = "TERMS_FOUND"
    TERMS_ABSENT = "TERMS_ABSENT"
    LEAK_FOUND = "LEAK_FOUND"
    NO_LEAK = "NO_LEAK"
    SIGNATURE_PRESENT = "SIGNATURE_PRESENT"
    SIGNATURE_ABSENT = "SIGNATURE_ABSENT"
    BLOCKED = "BLOCKED"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    NO_PARAMETER = "NO_PARAMETER"  # 検証済み引用に検査に使える値（字数の上限など）が無く、チェッカーを走らせられない
    ERROR = "ERROR"


class ObsOutcome(StrEnum):
    """観測の結末。判定表は pass / fail と strong の組で判定する。"""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"  # 不確定。方針変更の自動検出（§3 c）に使う


class FeatureCategory(StrEnum):
    """DocFeatures の語彙カテゴリ（12。§3）。コード算出の命中数だけを Planner に見せる。"""

    ACCOUNT = "account"
    AUTH = "auth"
    DEMO = "demo"
    VIDEO = "video"
    LICENSE = "license"
    DEADLINE = "deadline"
    CHAR_LIMIT = "char_limit"
    REPOSITORY = "repository"
    DEPLOY = "deploy"
    CONTACT = "contact"
    URL = "url"
    GUIDANCE = "guidance"


class HiddenKind(StrEnum):
    """隠しチャネルの由来（§5-2 層0。インライン style と属性のみ判定）。"""

    CSS_DISPLAY_NONE = "css_display_none"
    CSS_VISIBILITY_HIDDEN = "css_visibility_hidden"
    HIDDEN_ATTR = "hidden_attr"
    ARIA_HIDDEN = "aria_hidden"
    CSS_OPACITY_ZERO = "css_opacity_zero"
    CSS_FONT_SIZE_ZERO = "css_font_size_zero"
    CSS_OFFSCREEN = "css_offscreen"
    INPUT_HIDDEN = "input_hidden"
    UNICODE_TAG = "unicode_tag"
    OTHER = "other"


class FetchMode(StrEnum):
    """FetchRequest の種別。page は ACQUIRE / fetch_link、probe は http_probe。"""

    PAGE = "page"  # ACQUIRE / fetch_link（本文を最大 1MiB）
    PROBE = "probe"  # http_probe（本文先頭 64KB）


class FetchKind(StrEnum):
    """取得の予算上の種別（§3 RUN_CAPS: ACQUIRE 最大3＋fetch_link 最大3＋http_probe 最大2）。FetchMode とは別軸。"""

    ACQUIRE = "acquire"
    FETCH_LINK = "fetch_link"
    HTTP_PROBE = "http_probe"


class ContentKind(StrEnum):
    """許可リストの Content-Type 種別（§4）。"""

    HTML = "html"
    XHTML = "xhtml"
    PLAIN = "plain"
    MARKDOWN = "markdown"
    JSON = "json"
    UNSUPPORTED = "unsupported"


class FetchOutcome(StrEnum):
    """取得の結末。想定内の失敗は例外でなくこの値で返す。"""

    OK = "ok"
    BLOCKED = "blocked"  # スコープ・SSRF 規則で拒否（blocked_policy が付く）
    UNSUPPORTED_TYPE = "unsupported_type"
    TOO_LARGE = "too_large"  # Content-Length が上限超で読まなかった
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    TOO_MANY_REDIRECTS = "too_many_redirects"


class FetchLimit(StrEnum):
    """上限到達の理由（§5-3）。"""

    DECODED_SIZE = "decoded_size"  # デコード後 1MiB
    PROBE_PREFIX = "probe_prefix"  # http_probe の先頭 64KB
    CONTENT_LENGTH = "content_length"  # 3MB 超を読む前に拒否
    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    TOTAL_TIMEOUT = "total_timeout"
    REDIRECTS = "redirects"


class BudgetDimension(StrEnum):
    """予算の次元。Budget.exhausted() が、どれが先に尽きたかを返す。"""

    MODEL_CALLS = "model_calls"
    TOKENS_IN = "tokens_in"
    TOKENS_OUT = "tokens_out"
    TOOL_CALLS = "tool_calls"
    FETCHES = "fetches"
    THIRD_PARTY_ORIGINS = "third_party_origins"
    WALL_CLOCK = "wall_clock"


class QuoteStepOutcome(StrEnum):
    """quote_check の1ステップの結果。"""

    VERIFIED = "verified"
    REJECTED = "rejected"
    DEMOTED = "demoted"


class ReqState(StrEnum):
    """StateView に載る要件の状態。"""

    OPEN = "open"
    DONE = "done"
    UNVERIFIABLE = "unverifiable"


class ContradictionBasis(StrEnum):
    """矛盾に採用した根拠（§5-1。LLM の同 topic 主張は根拠にしない）。"""

    TOKEN_DIFF = "token_diff"  # 日付対日付・同単位の数値の相違
    EXCLUSIVE_ATTRIBUTES = "exclusive_attributes"  # 現地↔オンライン等の排他属性ペア


# ---------------------------------------------------------------------------
# 取得スコープとプリセット（§2・§6-2）
# ---------------------------------------------------------------------------
class UrlPrefix(_Frozen):
    """取得スコープの1要素。origin でなく URL 接頭辞（host＋パス接頭辞。§2）。

    config が定義し、SafeFetch（T3）が照合する。ここでは形だけを検査し、照合は SafeFetch の責務。
    """

    host: str = Field(max_length=253)
    port: int = 443
    path_prefix: str = Field(default="/", max_length=512)
    # True なら path が path_prefix と完全一致する URL だけ（LP・FAQ の正確なURL、自サービスの "/" 用。§2）
    exact: bool = False

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if v != v.lower() or v.endswith(".") or "." not in v:
            raise ValueError("ホストは小文字・末尾ドット無し・ドット区切りの DNS 名だけ")
        label = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
        if not re.fullmatch(rf"{label}(\.{label})+", v):
            raise ValueError("DNS 名の形式ではありません")
        if v.rsplit(".", 1)[-1].isdigit():
            raise ValueError("IP リテラルは許可しません")
        if v == "localhost" or v.endswith((".local", ".localhost", ".internal")):
            raise ValueError("内部ホスト名は許可しません")
        return v

    @field_validator("port")
    @classmethod
    def _port(cls, v: int) -> int:
        if v != 443:
            raise ValueError("ポートは 443 のみ（§5-3）")
        return v

    @field_validator("path_prefix")
    @classmethod
    def _path(cls, v: str) -> str:
        if not re.fullmatch(r"/[A-Za-z0-9._~\-/]*", v):
            raise ValueError("パス接頭辞は / で始まり、英数と . _ ~ - / だけ")
        if any(seg in (".", "..") for seg in v.split("/")) or "//" in v:
            raise ValueError("パス接頭辞に . .. // は使えません")
        return v

    def matches(self, host: str, path: str) -> bool:
        """正規化済みの host（小文字・IDNA 済み）と path（posixpath.normpath 済み）がこの範囲に入るか。

        スコープ照合の唯一の定義（SafeFetch・Governor・Preset がこれを使う。§5-3 S-07）。
          * exact=True: path が path_prefix と完全一致する時だけ。
          * 末尾が "/" の接頭辞（"/fx/"）: その配下だけ（"/fx" や "/fxx/" は範囲外。"/" は全パス）。
          * 末尾が "/" でない接頭辞（"/event"）: そのパス自身と配下（セグメント境界で一致。"/eventx" は範囲外）。
        クエリ・fragment・パーセントエンコードの扱いは呼び出し側（validate_url）の責務で、ここへは来ない。
        """
        if host != self.host:
            return False
        if self.exact:
            return path == self.path_prefix
        if self.path_prefix.endswith("/"):
            return path.startswith(self.path_prefix)
        return path == self.path_prefix or path.startswith(self.path_prefix + "/")


# ---------------------------------------------------------------------------
# GitHub 公開リポジトリの固定ファイル取得（第7弾の土台。入口は app/github_repo.py、S3 の規則は net/safefetch.py）
# ---------------------------------------------------------------------------
# owner/repo の形と固定名の「唯一の定義」。入口の検証（github_repo.parse_repo_url）も S3 の許可規則（RepoRawScope.matches）も
# ここの関数を使う＝同じ事実を2か所で判定しない。
GITHUB_RAW_HOST = "raw.githubusercontent.com"
GITHUB_RAW_REF = "HEAD"
# 取得してよいファイルの名前（完全一致・大文字小文字を区別）。README と LICENSE は、この並びの先に見つかったものを使う。
REPO_FILE_NAMES: tuple[str, ...] = ("README.md", "README", "LICENSE", "LICENSE.md", "LICENSE.txt", "Dockerfile", "requirements.txt")
_GITHUB_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")  # 1〜39字・先頭と末尾はハイフンでない（ASCII だけ）
_GITHUB_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")


def is_github_owner(value: str) -> bool:
    return isinstance(value, str) and _GITHUB_OWNER.fullmatch(value) is not None


def is_github_repo(value: str) -> bool:
    """英数と . _ - の1〜100字。"." ".." と ".git" 終わり（大文字小文字を問わない）は不可。"""
    return (
        isinstance(value, str)
        and _GITHUB_REPO.fullmatch(value) is not None
        and value not in (".", "..")
        and not value.lower().endswith(".git")
    )


class RepoRawScope(_Frozen):
    """S3 の取得規則の1つ: 公開リポジトリの固定ファイルだけ（`UrlPrefix` とは別の型。既定は無効で、S3 の設定で明示的に有効にした時だけ働く）。

    URL 接頭辞では「owner/repo は任意・その先は固定名だけ」を表せない（接頭辞は `/owner/repo/HEAD/` までで、任意の owner/repo を
    許すと配下のどのパスも通る）。そこで形そのものを検査する別の型にし、`UrlPrefix.matches` の定義には手を入れない。
    host は raw.githubusercontent.com 固定、パスは `/<owner>/<repo>/HEAD/<固定名>` に完全一致、クエリ無し、ポートは URL 検証が 443 だけ。
    リダイレクトを追わない・本文の上限・バイナリの拒否は SafeFetch がこの規則で通った要求にだけ掛ける。
    """

    def matches(self, host: str, path: str) -> bool:
        """正規化済み（net.urlcheck.validate_url の後）の host と path が規則の形に完全一致するか。"""
        if host != GITHUB_RAW_HOST:
            return False
        parts = path.split("/")  # "/o/r/HEAD/README.md" → ["", "o", "r", "HEAD", "README.md"]
        if len(parts) != 5 or parts[0] != "":
            return False
        _, owner, repo, ref, name = parts
        return is_github_owner(owner) and is_github_repo(repo) and ref == GITHUB_RAW_REF and name in REPO_FILE_NAMES


# ---------------------------------------------------------------------------
# 要項モード（第11弾）: 利用者が入れた公開ページの URL を Reader だけにかける。S3 の別の取得規則
# ---------------------------------------------------------------------------
SPEC_URL_PRESET_ID = "spec_url"


class OpenPageScope(_Frozen):
    """S3 の取得規則の1つ: 公開ページを1ページだけ取る（`UrlPrefix`・`RepoRawScope` とは別の型。既定は無効で、S3 の設定
    SPEC_FETCH_ENABLED で明示的に有効にした時だけ働く）。

    許可リスト（URL 接頭辞）では「任意の公開ホストの1ページ」を表せないので別の型にし、`UrlPrefix.matches` の定義には手を入れない。
    host の形（IP の直書き・localhost・単一ラベル・.local/.internal 等の拒否）とポート 443 は net.urlcheck.validate_url が、
    私的・予約済みアドレスの拒否（DNS 解決後）は既存の GuardedResolver が見る。この型が見るのは、正規化の後の host・path が
    空でないことだけ（形の定義を2か所に持たない）。転送を追わない・GET の page だけ・text/html と text/plain だけ・本文の上限は、
    SafeFetch がこの規則で通った要求にだけ掛ける。許可リストに合う URL は従来どおり許可リストの扱い（この規則は使わない）。
    """

    def matches(self, host: str, path: str) -> bool:
        return bool(host) and "." in host and path.startswith("/")


# ---------------------------------------------------------------------------
# 「リポジトリの基本点検」の結果（第10弾。RunRecord とは別の型。要項の要件には結びつけない）
# ---------------------------------------------------------------------------
# 自由文を持てない型: 題名と理由は固定文の列挙型（値が日本語の固定文）、証拠のチップはコードの語彙の形だけ、
# 件数は整数。リポジトリの文面・URL・数値が埋め込まれる経路を、型で作らない。判定を書くのは adjudicate.py だけ。
GITHUB_REPO_PRESET_ID = "github_repo"
REPO_FETCH_NAMES: tuple[str, ...] = ("README", "LICENSE", "Dockerfile", "requirements.txt")
# github_repo.RepoFileStatus の値と同じ（tests/test_repo_audit.py が一致を固定する。contracts は github_repo に依存できない）
REPO_FETCH_STATUSES: tuple[str, ...] = ("found", "not_found", "rate_limited", "transient", "rejected", "unusable", "skipped")


class RepoItemId(StrEnum):
    """点検項目の ID（固定の3つ）。"""

    LICENSE = "license"
    README_LEAK = "readme_leak"
    TECH_TRACE = "tech_trace"


class RepoItemTitle(StrEnum):
    """点検項目の題名（固定文）。"""

    LICENSE = "ライセンスの表示"
    README_LEAK = "READMEに公開してはいけない情報が無いか"
    TECH_TRACE = "必須技術の痕跡"


class RepoReason(StrEnum):
    """理由の固定文（リポの中身・URL・数値を埋め込まない。件数は証拠のチップで示す）。"""

    LICENSE_PHRASES_PRESENT = "LICENSE に、標準のライセンスに特徴的な語句がそろっています。全文の一致と、リポジトリ全体への適用は確かめていません。"
    LICENSE_UNKNOWN = "ライセンスのファイルはありますが、種類を判定できません。ご自身で確認してください。"
    LICENSE_MISSING = "ライセンスのファイルが見つかりません。"
    LEAK_FOUND = "READMEに、公開してはいけない情報の形が見つかりました。種類と件数は証拠のとおりです。"
    LEAK_NONE = "READMEの走査では、公開してはいけない情報の形は見つかりませんでした。走査したのはREADMEだけです。"
    README_MISSING = "READMEが見つからないため、確かめていません。"
    README_EMPTY = "READMEは見つかりましたが、中身が空のため、確かめていません。"
    TECH_FOUND = "Google Cloud の AI 関連の固定辞書にあるパッケージの記載が見つかりました。どのファイルかは証拠のとおりです。"
    TECH_NOT_SEEN = "取得できたファイルに、固定辞書の記載は見つかりませんでした。この点検では、ほかの書き方での利用は見分けられません。"
    TECH_NO_FILES = "Dockerfile も requirements.txt も見つからないため、確かめていません。この点検では、ほかの書き方での利用は見分けられません。"
    UNCHECKED_RATE_LIMITED = "GitHub の回数制限で、いまは確かめられません。"
    UNCHECKED_TRANSIENT = "一時的な失敗で取得できず、確かめていません。"
    UNCHECKED_REJECTED = "取得が許可されなかったため、確かめていません。"
    UNCHECKED_UNUSABLE = "ファイルが大きすぎるか、テキストでないため、確かめていません。"
    UNCHECKED_SKIPPED = "取得しなかったため、確かめていません。"
    UNCHECKED_NO_FACT = "点検の結果を得られなかったため、確かめていません。"


_UNCHECKED_REASONS = frozenset(r for r in RepoReason if r.name.startswith("UNCHECKED_"))
# 項目ごとに言ってよい理由（それ以外の組み合わせは作れない）
REPO_ITEM_REASONS: dict[RepoItemId, frozenset[RepoReason]] = {
    RepoItemId.LICENSE: frozenset({RepoReason.LICENSE_PHRASES_PRESENT, RepoReason.LICENSE_UNKNOWN, RepoReason.LICENSE_MISSING}) | _UNCHECKED_REASONS,
    RepoItemId.README_LEAK: frozenset({RepoReason.LEAK_FOUND, RepoReason.LEAK_NONE, RepoReason.README_MISSING, RepoReason.README_EMPTY}) | _UNCHECKED_REASONS,
    RepoItemId.TECH_TRACE: frozenset({RepoReason.TECH_FOUND, RepoReason.TECH_NOT_SEEN, RepoReason.TECH_NO_FILES}) | _UNCHECKED_REASONS,
}
# 証拠のチップに載せてよい語彙（項目ごと）。ライセンスの識別子は checks.repo_inspect.LicenseKind、走査の種類名は leak_scan.LEAK_PATTERNS と
# 同じ（contracts は checks に依存できないので、ここに持ち、tests/test_repo_audit.py が一致を固定する）。
REPO_LICENSE_IDS: tuple[str, ...] = (
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-3.0", "LGPL-3.0", "AGPL-3.0", "MPL-2.0", "ISC", "Unlicense",
)  # fmt: skip
REPO_LEAK_KINDS: tuple[str, ...] = (
    "email", "service_account", "google_api_key", "oauth_token", "private_key", "github_token", "aws_key_id", "private_ip",
)  # fmt: skip
REPO_EVIDENCE_VOCAB: dict[RepoItemId, frozenset[str]] = {
    RepoItemId.LICENSE: frozenset(REPO_LICENSE_IDS),
    RepoItemId.README_LEAK: frozenset(REPO_LEAK_KINDS) | {"README"},
    RepoItemId.TECH_TRACE: frozenset({"Dockerfile", "requirements.txt"}),
}


REPO_EVIDENCE_CHIP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}(?: ×[1-9][0-9]{0,5})?")


class RepoEvidence(_Frozen):
    """証拠のチップ。コードの語彙（ライセンスの識別子・走査の種類名・ファイル名）と、あれば件数（「email ×2」）だけ。"""

    label: str

    @field_validator("label")
    @classmethod
    def _shape(cls, v: str) -> str:
        if REPO_EVIDENCE_CHIP.fullmatch(v) is None:
            raise ValueError("証拠のチップの形ではありません")
        return v


class RepoItem(_Frozen):
    """点検の1項目。ラベルは既存の5種のうち適合・推定適合・不適合・確認不能だけを使う（ライセンスの項目は適合を出せない）。"""

    id: RepoItemId
    title_ja: RepoItemTitle
    label: VerdictLabel
    reason_ja: RepoReason
    evidence: tuple[RepoEvidence, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def _consistent(self) -> "RepoItem":
        if self.title_ja.name != self.id.name:
            raise ValueError("題名が項目と合いません")
        if self.reason_ja not in REPO_ITEM_REASONS[self.id]:
            raise ValueError("この項目で言ってよい理由ではありません")
        if self.label in (VerdictLabel.PASS, VerdictLabel.PRESUMED_PASS) and not self.evidence:
            raise ValueError("適合・推定適合には証拠が要ります")
        if self.label is VerdictLabel.REFERENCE:
            raise ValueError("この点検に参考はありません")
        if self.id is RepoItemId.LICENSE and self.label is VerdictLabel.PASS:
            raise ValueError("ライセンスは語句の判定なので、適合は出せません（推定適合まで）")
        vocab = REPO_EVIDENCE_VOCAB[self.id]
        for e in self.evidence:
            if e.label.split(" ×")[0] not in vocab:
                raise ValueError("この項目の証拠にできない語です")
        return self


class RepoFetched(_Frozen):
    """固定ファイル1種の取得の状態。"""

    name: Literal["README", "LICENSE", "Dockerfile", "requirements.txt"]
    status: Literal["found", "not_found", "rate_limited", "transient", "rejected", "unusable", "skipped"]


class RepoWarning(_Frozen):
    """警告。判定には使わない（件数だけ）。"""

    code: Literal["INJECTION_SUSPECTED"]
    count: int = Field(ge=1, le=1_000_000)


class RepoSummary(_Frozen):
    """判定ラベルごとの件数。"""

    verdict_counts: dict[VerdictLabel, int]


class RepoAuditResult(_Frozen):
    """SSE の `result` に載る、リポジトリの基本点検の結果（固定3項目）。RunRecord ではない。"""

    kind: Literal["repo_audit"] = "repo_audit"
    mode: Literal["LIVE"] = "LIVE"
    status: Literal["DONE"] = "DONE"
    preset_id: Literal["github_repo"] = GITHUB_REPO_PRESET_ID
    items: tuple[RepoItem, ...] = Field(min_length=3, max_length=3)
    fetched: tuple[RepoFetched, ...] = Field(min_length=4, max_length=4)
    warnings: tuple[RepoWarning, ...] = Field(default=(), max_length=1)
    summary: RepoSummary

    @model_validator(mode="after")
    def _consistent(self) -> "RepoAuditResult":
        if [i.id for i in self.items] != list(RepoItemId):
            raise ValueError("項目は固定の3つを決まった順で")
        if [f.name for f in self.fetched] != list(REPO_FETCH_NAMES):
            raise ValueError("取得の状態は固定の4つを決まった順で")
        counts = {lab: sum(1 for i in self.items if i.label is lab) for lab in VerdictLabel}
        if self.summary.verdict_counts != counts:
            raise ValueError("集計が項目と合いません")
        return self


class PresetKind(StrEnum):
    """プリセットの種類（§9 の3本のデモに対応）。"""

    LIVE_LP = "live_lp"  # ① 実在 LP＋自己監査
    FIXTURE_DEFECT = "fixture_defect"  # ② 欠陥入りの架空サンプル
    FIXTURE_INJECTION = "fixture_injection"  # ③ 偽の命令入りの架空サンプル
    SPEC_URL = "spec_url"  # 要項モード（第11弾。審査員コード用。要件の一覧だけ）


class Preset(_Frozen):
    """プリセット1種。公開面の入力はこの ID だけで、取得先もここに固定される（§6-2 閉世界）。"""

    preset_id: PresetId
    label_ja: Display40
    kind: PresetKind
    spec_seed_urls: tuple[HttpsUrl, ...] = Field(max_length=3)  # 要項側のシード（最大3）
    submission_url: HttpsUrl | None = None  # SUBMISSION_URL（検査される提出物。http_probe の SUBMISSION_URL はこれ）
    # 提出物の説明ページ（第3弾で追加）。ACQUIRE が提出物の文書として取得する。None なら submission_url を取得する。
    # デプロイURL（submission_url）がログイン壁でも、公開説明文の字数・漏洩は説明ページで検査できるようにするため（プリセット②③）
    submission_page_url: HttpsUrl | None = None
    allowed_prefixes: tuple[UrlPrefix, ...] = Field(max_length=8)

    @model_validator(mode="after")
    def _seeds_in_scope(self) -> "Preset":
        extra = [u for u in (self.submission_url, self.submission_page_url) if u]
        if self.submission_page_url and not self.submission_url:
            raise ValueError("submission_page_url は submission_url と組で使います")
        for u in (*self.spec_seed_urls, *extra):
            parts = urlsplit(u)
            host = (parts.hostname or "").lower()
            path = parts.path or "/"
            if not any(p.matches(host, path) for p in self.allowed_prefixes):
                raise ValueError("シード／提出URLが allowed_prefixes の外にあります")
        return self


# ---------------------------------------------------------------------------
# 実行ごとの上限と予算（§3 RUN_CAPS）
# ---------------------------------------------------------------------------
class RunCaps(_Frozen):
    """実行ごとの上限。値は config.RUN_CAPS が持ち、コードが強制する（Governor）。"""

    model_calls_reader: int = Field(gt=0)
    model_calls_planner: int = Field(gt=0)
    model_calls_spare: int = Field(ge=0)
    model_call_timeout_s: float = Field(gt=0)
    model_retries: int = Field(ge=0)  # 429/5xx のみ
    retry_backoff_s: tuple[float, ...]
    tokens_in: int = Field(gt=0)
    tokens_out: int = Field(gt=0)  # thinking 含む
    thinking_budget_reader: int = Field(ge=0)
    thinking_budget_planner: int = Field(ge=0)
    tool_calls: int = Field(gt=0)  # AUTORUN 分を含む
    fetches_acquire: int = Field(ge=0)
    fetches_fetch_link: int = Field(ge=0)
    fetches_probe: int = Field(ge=0)
    third_party_origins: int = Field(ge=0)
    requirements_obligatory: int = Field(gt=0)  # 必須・禁止
    requirements_speculative: int = Field(ge=0)
    requirements_optional: int = Field(ge=0)
    requirements_request: int = Field(ge=0)
    quote_verify_max_chars: int = Field(gt=0)
    quote_display_max_chars: int = Field(gt=0)
    wall_clock_s: float = Field(gt=0)
    planner_max_turns: int = Field(gt=0)
    tool_calls_per_requirement: int = Field(gt=0)
    consecutive_denials_stop: int = Field(default=3, gt=0)  # 拒否が連続したら DEGRADED（§3 停止）
    reader_total_chars: int = Field(gt=0)  # spec 文書の合計（超過は TRUNCATED）
    reader_chunk_chars: int = Field(gt=0)
    reader_chunk_overlap: int = Field(ge=0)
    reader_max_parallel: int = Field(gt=0)

    @model_validator(mode="after")
    def _sane(self) -> "RunCaps":
        if self.reader_chunk_overlap >= self.reader_chunk_chars:
            raise ValueError("reader_chunk_overlap は reader_chunk_chars より小さく")
        if self.quote_display_max_chars > self.quote_verify_max_chars:
            raise ValueError("表示上限は検証上限以下")
        return self

    @property
    def model_calls_total(self) -> int:
        return self.model_calls_reader + self.model_calls_planner + self.model_calls_spare

    @property
    def fetches_total(self) -> int:
        return self.fetches_acquire + self.fetches_fetch_link + self.fetches_probe


class BudgetSnapshot(_Frozen):
    """残予算（StateView と budget_snapshot イベントに載る。数値だけ）。"""

    model_calls_left: int = Field(ge=0)
    tokens_in_left: int = Field(ge=0)
    tokens_out_left: int = Field(ge=0)
    tool_calls_left: int = Field(ge=0)
    fetches_left: int = Field(ge=0)
    third_party_origins_left: int = Field(ge=0)
    wall_ms_left: int = Field(ge=0)


class Budget(_Strict):
    """1実行の予算の使用状況（可変）。上限は caps、使った量はカウンタ。

    Governor（T7）が呼び出しの前に can_* で確認し、後に charge_* で計上する。
    切断・タイムアウトで usage が戻らない呼び出しは、呼び出し側が最悪値で charge する（§6-1）。
    """

    model_config = ConfigDict(validate_assignment=True)

    caps: RunCaps
    reader_calls: int = Field(default=0, ge=0)
    planner_calls: int = Field(default=0, ge=0)
    tokens_in: int = Field(default=0, ge=0)
    tokens_out: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    fetches: int = Field(default=0, ge=0)  # 取得の合計（種別ごとの内訳は fetches_by_kind）
    fetches_by_kind: dict[FetchKind, int] = Field(default_factory=dict)
    third_party_origins: tuple[Token, ...] = ()  # 取得した第三者 origin（host 別名）。重複なし
    elapsed_ms: int = Field(default=0, ge=0)  # 壁時計。呼び出し側が時計から更新する

    @property
    def model_calls(self) -> int:
        return self.reader_calls + self.planner_calls

    def _overflow(self, reader: int, planner: int) -> int:
        """専用枠（Reader 10・Planner 8）を超えた分＝予備枠（4）の使用量。"""
        return max(0, reader - self.caps.model_calls_reader) + max(0, planner - self.caps.model_calls_planner)

    def can_call_model(self, purpose: ModelPurpose, est_tokens_in: int = 0, max_output_tokens: int = 0) -> bool:
        return (
            self._slot_free(purpose)
            and self.tokens_in + est_tokens_in <= self.caps.tokens_in
            and self.tokens_out + max_output_tokens <= self.caps.tokens_out
            and self.elapsed_ms < self.caps.wall_clock_s * 1000
        )

    def charge_model_call(self, purpose: ModelPurpose, tokens_in: int, tokens_out: int) -> None:
        if purpose is ModelPurpose.READER:
            self.reader_calls += 1
        else:
            self.planner_calls += 1
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out

    def can_call_tool(self) -> bool:
        return self.tool_calls < self.caps.tool_calls

    def charge_tool_call(self) -> None:
        self.tool_calls += 1

    def kind_cap(self, kind: FetchKind) -> int:
        """種別ごとの取得上限（ACQUIRE 3・fetch_link 3・http_probe 2。§3）。"""
        c = self.caps
        return {
            FetchKind.ACQUIRE: c.fetches_acquire,
            FetchKind.FETCH_LINK: c.fetches_fetch_link,
            FetchKind.HTTP_PROBE: c.fetches_probe,
        }[kind]

    def can_fetch(self, third_party_origin: str | None = None, kind: FetchKind | None = None) -> bool:
        """取得できるか。kind を渡すと、合計（8）に加えて種別ごとの上限も見る（http_probe は1実行2回まで。§4）。"""
        if self.fetches >= self.caps.fetches_total:
            return False
        if kind is not None and self.fetches_by_kind.get(kind, 0) >= self.kind_cap(kind):
            return False
        if third_party_origin is not None and third_party_origin not in self.third_party_origins:
            return len(self.third_party_origins) < self.caps.third_party_origins
        return True

    def charge_fetch(self, third_party_origin: str | None = None, kind: FetchKind | None = None) -> None:
        self.fetches += 1
        if kind is not None:
            self.fetches_by_kind = {**self.fetches_by_kind, kind: self.fetches_by_kind.get(kind, 0) + 1}
        if third_party_origin is not None and third_party_origin not in self.third_party_origins:
            self.third_party_origins = (*self.third_party_origins, third_party_origin)

    def _slot_free(self, purpose: ModelPurpose) -> bool:
        r = self.reader_calls + (1 if purpose is ModelPurpose.READER else 0)
        p = self.planner_calls + (1 if purpose is ModelPurpose.PLANNER else 0)
        return self._overflow(r, p) <= self.caps.model_calls_spare

    def exhausted(self) -> BudgetDimension | None:
        """上限に達している最初の次元。無ければ None。"""
        c = self.caps
        if not self._slot_free(ModelPurpose.READER) and not self._slot_free(ModelPurpose.PLANNER):
            return BudgetDimension.MODEL_CALLS
        if self.tokens_in >= c.tokens_in:
            return BudgetDimension.TOKENS_IN
        if self.tokens_out >= c.tokens_out:
            return BudgetDimension.TOKENS_OUT
        if self.tool_calls >= c.tool_calls:
            return BudgetDimension.TOOL_CALLS
        if self.fetches >= c.fetches_total:
            return BudgetDimension.FETCHES
        if self.elapsed_ms >= c.wall_clock_s * 1000:
            return BudgetDimension.WALL_CLOCK
        return None

    def snapshot(self) -> BudgetSnapshot:
        c = self.caps
        return BudgetSnapshot(
            model_calls_left=max(0, c.model_calls_total - self.model_calls),
            tokens_in_left=max(0, c.tokens_in - self.tokens_in),
            tokens_out_left=max(0, c.tokens_out - self.tokens_out),
            tool_calls_left=max(0, c.tool_calls - self.tool_calls),
            fetches_left=max(0, c.fetches_total - self.fetches),
            third_party_origins_left=max(0, c.third_party_origins - len(self.third_party_origins)),
            wall_ms_left=max(0, int(c.wall_clock_s * 1000) - self.elapsed_ms),
        )


# ---------------------------------------------------------------------------
# Reader の出力（LLM 出力型。非信頼）
# ---------------------------------------------------------------------------
class RawRequirement(_Frozen):
    """Reader（Gemini・ツール無し）が返す要件候補。非信頼データ。

    verified / locator / doc_id / 位置を持たない（モデルの申告は無視する。出典はコードの検索結果）。
    quotes.verify を通った分だけが VerifiedRequirement になる。
    """

    quote: str = Field(min_length=1, max_length=600)  # 検証で 160 字超は too_long。多めに受けて検証側で弾く
    kind: Kind
    check_class: CheckClass = CheckClass.NONE
    slot: Slot = Slot.NONE
    # 非信頼の言い換え。引用が検証できず推測へ降格した時の表示にだけ使う。
    # VerifiedRequirement.gist（表示用の安全文字のみ）へ載せる前に textsafe.strip_unsafe を通すこと。
    gist: str = Field(default="", max_length=REASON_MAX_CHARS)


class LinkRoleGuess(_Frozen):
    """Reader が付けるリンク役割の提案。href・アンカーは返させない（link_id だけ）。"""

    link_id: LinkId
    role: LinkRole


class ReaderOutput(_Frozen):
    """Reader の1チャンク分の出力（response_schema 強制）。Reader が作り、quotes / ACQUIRE が読む。"""

    page_class: PageClass
    requirements: list[RawRequirement] = Field(default_factory=list, max_length=40)
    link_roles: list[LinkRoleGuess] = Field(default_factory=list, max_length=60)


# ---------------------------------------------------------------------------
# 引用検証の結果と VerifiedRequirement（§5-1。型分離）
# ---------------------------------------------------------------------------
class VerificationSeal:
    """検証済みの印。DocIndex（quotes.py）だけが issue する。

    Python は真の private を持てないので、(1) 発行点を `VerificationSeal.issue(` の1種類に絞り、
    (2) tests/test_contracts.py が quotes.py 以外の app/ 配下に発行点が無いことを grep で固定する。
    保証の本体は REPORT での最終再検証（全引用をもう一度 DocStore に当てる）。
    """

    __slots__ = ("issuer",)
    _KEY = object()

    def __init__(self, *, _key: object, issuer: str) -> None:
        if _key is not VerificationSeal._KEY:
            raise TypeError("VerificationSeal は VerificationSeal.issue() で発行する")
        self.issuer = issuer

    @classmethod
    def issue(cls, issuer: str) -> "VerificationSeal":
        return cls(_key=cls._KEY, issuer=issuer)

    def __repr__(self) -> str:
        return f"VerificationSeal(issuer={self.issuer!r})"


class UnverifiedConstructionError(TypeError):
    """VerificationSeal 無しに VerifiedRequirement を作ろうとした。"""


class UnverifiedSerializationError(TypeError):
    """VerifiedRequirement でないものを REPORT / UI へシリアライズしようとした。"""


class VerifiedSpan(_Frozen):
    """引用検証の合格結果（設計の `Verified`）。DocIndex だけが作る。

    start/end は SanitizedDoc.visible_text 上のオフセット。original_span は拡張後の1文（コード生成）で、
    モデルの引用文字列は破棄している（ゼロ幅・bidi・タグ文字が画面に残らない）。
    """

    doc_id: DocId
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    original_span: Display160 = Field(min_length=1)
    occurrences: int = Field(ge=1)
    # 同梱の REPLAY だけが True にする（第三者の原文を短くして持つ。start/end は元の位置のまま）。
    # True の span は原文との照合に使えない＝再生時に再検証しない（保存時に検証済みの印だけを見せる）
    quote_clipped: bool = False

    @model_validator(mode="after")
    def _span(self) -> "VerifiedSpan":
        if self.end <= self.start:
            raise ValueError("end は start より大きく")
        n, width = len(self.original_span), self.end - self.start
        if self.quote_clipped:
            if n > width:
                raise ValueError("切り詰めた original_span が元の区間より長いです")
        elif n != width:
            raise ValueError("original_span の長さが end-start と一致しません")
        return self


class VerifiedRequirement(_Frozen):
    """検証を通った要件。REPORT / UI のシリアライザが受けるのはこの型だけ。

    作れるのは VerificationSeal を持つ者だけ（コンストラクタが seal を要求する）。
    span が無いのは「引用が逐語一致せず推測へ降格（または申告が推測のまま引用を検証できず）」した要件だけで、
    その表示は gist（モデルの推論）を使う。いずれも demotion=QUOTE_UNVERIFIED・kind=推測。
    """

    req_id: ReqId
    kind: Kind  # コード側クロスチェック後の最終 kind
    declared_kind: Kind  # モデルが申告した kind
    check_class: CheckClass = CheckClass.NONE
    slot: Slot = Slot.NONE
    span: VerifiedSpan | None
    demotion: DemotionReason | None = None
    chips: tuple[Chip, ...] = ()
    gist: Reason140 = ""  # span が無い（推測）ときだけ意味を持つモデルの推論
    reverified: bool = False  # REPORT の最終再検証を通した印（§3）

    def __init__(self, /, *, seal: VerificationSeal | None = None, **data: Any) -> None:
        if not isinstance(seal, VerificationSeal):
            raise UnverifiedConstructionError(
                "VerifiedRequirement は VerificationSeal（DocIndex が発行）無しには作れません"
            )
        super().__init__(**data)

    @model_validator(mode="after")
    def _invariants(self) -> "VerifiedRequirement":
        if self.span is None:
            if self.kind is not Kind.SPECULATIVE or self.demotion is not DemotionReason.QUOTE_UNVERIFIED:
                raise ValueError("引用（span）が無いのは、検証不合格で推測へ降格した要件だけ")
        else:
            if self.demotion is DemotionReason.QUOTE_UNVERIFIED:
                raise ValueError("引用が検証済みなら quote_unverified の降格はありえません")
            if self.gist:
                raise ValueError("引用が検証済みの要件にモデルの言い換え（gist）は載せません")
        if self.demotion is None:
            if self.kind is not self.declared_kind:
                raise ValueError("降格理由が無いのに kind が申告と違います")
        else:
            if self.kind is not DEMOTION_RESULT_KIND[self.demotion]:
                raise ValueError("降格理由と最終 kind が対応しません")
            # 申告が推測のまま引用だけ検証できなかった場合（quote_unverified）は、kind が変わらなくてよい
            # （「降格」ではなく「引用なしの推測」。サマリの K 件にも数えない）。他の降格は kind が変わる時だけ。
            if self.declared_kind is self.kind and self.demotion is not DemotionReason.QUOTE_UNVERIFIED:
                raise ValueError("降格理由があるのに kind が申告と同じです")
        if self.demotion is DemotionReason.NEGATION_OR_EXCEPTION and Chip.NEGATION_OR_EXCEPTION not in self.chips:
            raise ValueError("否定・例外による降格にはチップが必要です")
        if self.demotion is DemotionReason.REQUEST_WORDING and Chip.REQUEST_WORDING not in self.chips:
            raise ValueError("依頼文言による降格にはチップが必要です")
        return self

    @classmethod
    def restore(cls, data: Mapping[str, Any], *, seal: VerificationSeal) -> "VerifiedRequirement":
        """保存済みの記録から復元する（seal を持つ呼び出し側だけ）。"""
        return cls(seal=seal, **dict(data))

    def display_quote(self, max_chars: int) -> str:
        """画面に出す引用（拡張後の1文の先頭 max_chars 字）。span が無ければ空。"""
        if self.span is None:
            return ""
        s = self.span.original_span
        return s if len(s) <= max_chars else s[: max(max_chars - 1, 0)] + "…"

    def mark_reverified(self, seal: VerificationSeal) -> "VerifiedRequirement":
        if not isinstance(seal, VerificationSeal):
            raise UnverifiedConstructionError("再検証の印には VerificationSeal が要ります")
        return self.model_copy(update={"reverified": True})


# ---------------------------------------------------------------------------
# 入口の洗浄の出力（§5-2。T4 が作り、T5・T6・T8 が読む）
# ---------------------------------------------------------------------------
class LinkEntry(_Frozen):
    """リンク表 L1… の1行。href はモデルへ渡さない。fetch_link は link_id だけで指す（§4）。"""

    link_id: LinkId
    href: str = Field(max_length=2048)
    anchor_text: Display200  # 非信頼。Reader だけが見る（Planner は見ない）
    role: LinkRole = LinkRole.OTHER
    in_scope: bool = False  # スコープ外は登録時に落として link_rejected をトレースへ（§3 ACQUIRE）


class HiddenChannel(_Frozen):
    """可視テキストから分離した隠しチャネル。本文は持たない（長さと sha256 と由来だけ）。

    submission の隠しチャネルはどのモデルにも渡さない（§5-2）。ここに本文を置けない型にしてある。
    """

    kind: HiddenKind
    length: int = Field(ge=0)
    sha256: Sha256Hex


class InjectionSignal(_Frozen):
    """偽命令（プロンプトインジェクション）の検知1件（§5-2 層1）。

    可視: visible_text 上の置換区間（INJECTION_PLACEHOLDER の位置）を start/end で持つ。
    隠し: 本文を持てないので start/end は無く、channel（SanitizedDoc.hidden の添字）で指す。
    """

    pattern_id: Token
    doc_id: DocId
    visible: bool
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, gt=0)
    channel: int | None = Field(default=None, ge=0)
    snippet: Display60 = ""  # エスケープ済み（textsafe.escape_for_display）

    @model_validator(mode="after")
    def _shape(self) -> "InjectionSignal":
        if self.visible:
            if self.start is None or self.end is None or self.end <= self.start or self.channel is not None:
                raise ValueError("可視の検知には start<end の区間が要り、channel は持てません")
        elif self.start is not None or self.end is not None or self.channel is None:
            raise ValueError("隠しの検知は channel を持ち、区間は持てません")
        return self


class DocFeatures(_Frozen):
    """コード算出の文書特徴（§3 StateView）。Planner が生テキスト無しで routes を選ぶための数値。"""

    length: int = Field(ge=0)
    category_hits: dict[FeatureCategory, int] = Field(default_factory=dict)
    link_role_counts: dict[LinkRole, int] = Field(default_factory=dict)

    @field_validator("category_hits", "link_role_counts")
    @classmethod
    def _non_negative(cls, v: dict[Any, int]) -> dict[Any, int]:
        if any(n < 0 for n in v.values()):
            raise ValueError("件数は 0 以上")
        return v


class DocMeta(_Frozen):
    """文書の本文を持たないメタ。RunRecord・UI の出典表示用（本文は保存しない。§2）。"""

    doc_id: DocId
    role: DocRole
    label: Display80  # 表示名。URL・ホストを含めない（別名化済み）
    sha256: Sha256Hex
    byte_length: int = Field(ge=0)
    truncated: bool = False
    page_class: PageClass


class PageSignals(_Frozen):
    """コード算出のページ指標。page_class の裏取りと auth_wall の観測に使う（§3 AUTORUN・§4 http_probe）。

    Reader が「login_wall / error_page / empty / spa_shell」と申告しても、これと可視テキストの長さで
    コードが裏取りできた時だけ採用する（検査を減らす方向の出力はコードが確認＝S-03）。
    """

    http_status: int | None = Field(default=None, ge=100, le=599)  # 最終応答のステータス
    has_password_input: bool = False  # <input type=password> がある（hidden 以外の入力欄として）
    script_count: int = Field(default=0, ge=0)  # <script> の数（spa_shell の裏取り）


class SanitizedDoc(_Frozen):
    """sanitize の出力＝DocStore の1件（§3 ACQUIRE）。T4 が作り、T5・T6・T8・T9 が読む。

    visible_text は可視テキストのみ（索引化・Reader への入力はこれだけ）。ブロック境界 U+001E を含み、
    ゼロ幅・bidi・タグ文字・制御文字（\\n・\\t・U+001E 以外）は含められない。
    注入パターンに一致した区間は INJECTION_PLACEHOLDER に置換済みで、そこからは引用できない。
    """

    doc_id: DocId
    role: DocRole
    label: Display80
    url: str = Field(max_length=2048)  # 非公開。モデル・UI・トレースへ出さない（host は別名化）
    sha256: Sha256Hex  # 取得バイトの sha256
    byte_length: int = Field(ge=0)
    truncated: bool = False  # 取得の打切り（FetchResult.truncated）、または Reader の読み残し（reader_total_chars 超過）
    page_class: PageClass  # コード算出（T4）。Reader の申告は signals で裏取りできた時だけ T6 が反映する
    signals: PageSignals = Field(default_factory=PageSignals)
    visible_text: Annotated[str, AfterValidator(_text_safe)]
    links: tuple[LinkEntry, ...] = ()
    hidden: tuple[HiddenChannel, ...] = ()
    injection_signals: tuple[InjectionSignal, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> "SanitizedDoc":
        ids = [lk.link_id for lk in self.links]
        if len(set(ids)) != len(ids):
            raise ValueError("link_id が重複しています")
        n = len(self.visible_text)
        for s in self.injection_signals:
            if s.doc_id != self.doc_id:
                raise ValueError("InjectionSignal の doc_id が文書と一致しません")
            if s.visible and s.end is not None and s.end > n:
                raise ValueError("可視の検知区間が visible_text の外です")
            if not s.visible and s.channel is not None and s.channel >= len(self.hidden):
                raise ValueError("隠しの検知が存在しない channel を指しています")
        return self

    def meta(self) -> DocMeta:
        return DocMeta(
            doc_id=self.doc_id,
            role=self.role,
            label=self.label,
            sha256=self.sha256,
            byte_length=self.byte_length,
            truncated=self.truncated,
            page_class=self.page_class,
        )

    @property
    def injection_counts(self) -> tuple[int, int]:
        """(可視N件, 隠しM件)。警告帯の表示用（§5-2 層5）。"""
        vis = sum(1 for s in self.injection_signals if s.visible)
        return vis, len(self.injection_signals) - vis


# ---------------------------------------------------------------------------
# 取得（§5-3。SafeFetch の入出力。T3 が実装し、ACQUIRE / ツールが読む）
# ---------------------------------------------------------------------------
class FetchRequest(_Frozen):
    """FetchPort への要求。url は SafeFetch が検証する前の文字列。スコープは FetchPort 実装側が持つ。"""

    url: str = Field(min_length=1, max_length=4096)
    mode: FetchMode = FetchMode.PAGE


# SafeFetch が拒否に使える policy_id（URL 検証・スコープ外は P-SCOPE-01、DNS 解決後の非グローバル IP は P-SSRF-IP-01）
FETCH_BLOCK_POLICIES = frozenset({PolicyId.SCOPE, PolicyId.SSRF_IP})


class RedirectHop(_Frozen):
    """リダイレクト応答（3xx）1つ。スコープ外・非グローバルへの転送は追跡せず Location だけ記録する（§5-3）。

    url はこの 3xx を返した URL、location はその Location ヘッダ（生・追跡前）。
    追跡しなかった理由は blocked_policy（スコープ外 P-SCOPE-01／非グローバル IP P-SSRF-IP-01）で残す
    （各ホップの再検査がトレースに出る＝§9 デモ② D2）。上限（3ホップ）到達で追跡しなかった場合は理由なし。
    """

    url: str = Field(max_length=2048)
    status: int = Field(ge=300, le=399)
    location: str | None = Field(default=None, max_length=2048)
    followed: bool = False  # 検査を通って追跡したか
    in_scope: bool = False
    blocked_policy: PolicyId | None = None  # 追跡しなかった理由（followed=False の時だけ）

    @model_validator(mode="after")
    def _hop(self) -> "RedirectHop":
        if self.followed and (not self.in_scope or self.blocked_policy is not None):
            raise ValueError("追跡したホップは範囲内で、拒否理由を持てません")
        if self.blocked_policy is not None and self.blocked_policy not in FETCH_BLOCK_POLICIES:
            raise ValueError("ホップの拒否理由は P-SCOPE-01 / P-SSRF-IP-01 だけ")
        return self


class FetchResult(_Frozen):
    """SafeFetch の出力。FetchPort.fetch が返し、sanitize と http_probe の観測が読む。

    想定内の失敗（拒否・上限・タイムアウト）は例外でなく outcome で表す。
    不変条件: ok⇒status あり／blocked⇒blocked_policy あり・本文なし・転送なし／truncated⇒limit_hit あり。

    リダイレクトの表し方（T3 が作り、T4 の page_class・T9 の auth_wall が読む。ここで1通りに決める）:
      * redirects は受けた 3xx 応答を順に1つずつ（最後に追跡しなかったものも含む）。最後以外は必ず followed。
      * 追跡を通った転送は followed=True。最終応答（status・headers・body）は最後に取れた応答のもの。
      * スコープ外・非グローバル IP・http・非443 への転送で止めた場合は BLOCKED にせず outcome=ok・status=その 3xx・
        最後のホップが followed=False（blocked_policy 付き）。final_url はその 3xx を返した URL。認証壁の証拠になる。
      * 上限（3ホップ）を超える転送は outcome=too_many_redirects・最後のホップが followed=False。
      * outcome=blocked は最初のリクエストの拒否だけ（転送の途中では使わない）。
    headers の値は T3 が textsafe.strip_unsafe・300字切りをしてから載せる（違反すると ValidationError になる）。
    """

    requested_url: str = Field(max_length=2048)
    final_url: str | None = Field(default=None, max_length=2048)
    redirects: tuple[RedirectHop, ...] = Field(default=(), max_length=MAX_REDIRECT_HOPS + 1)
    outcome: FetchOutcome
    status: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)  # 許可リストのみ・キーは小文字
    body: bytes = Field(default=b"", max_length=FETCH_BODY_MAX_BYTES, repr=False)
    truncated: bool = False
    content_kind: ContentKind | None = None
    limit_hit: FetchLimit | None = None
    blocked_policy: PolicyId | None = None
    elapsed_ms: int = Field(default=0, ge=0)

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str]) -> dict[str, str]:
        for k, val in v.items():
            if k != k.lower() or k not in ALLOWED_RESPONSE_HEADERS:
                raise ValueError("許可リスト外の応答ヘッダは載せられません")
            if len(val) > 300 or not is_safe_text(val, allow_block_sep=False):
                raise ValueError("ヘッダ値が長すぎる、または安全でない文字を含みます")
        return v

    @model_validator(mode="after")
    def _invariants(self) -> "FetchResult":
        o = self.outcome
        if o is FetchOutcome.OK and self.status is None:
            raise ValueError("outcome=ok には status が要ります")
        if o is FetchOutcome.BLOCKED:
            if self.blocked_policy is None or self.status is not None or self.body or self.redirects:
                raise ValueError("blocked には blocked_policy が要り、status・本文・転送は持てません")
            if self.blocked_policy not in FETCH_BLOCK_POLICIES:
                raise ValueError("blocked_policy は P-SCOPE-01 / P-SSRF-IP-01 だけ")
        elif self.blocked_policy is not None:
            raise ValueError("blocked_policy は outcome=blocked の時だけ")
        if any(not h.followed for h in self.redirects[:-1]):
            raise ValueError("最後以外の転送は追跡済みのはず（追跡しなかった時点でそこが最後）")
        if sum(1 for h in self.redirects if h.followed) > MAX_REDIRECT_HOPS:
            raise ValueError("追跡する転送は最大3ホップ")
        if self.truncated and (self.limit_hit not in (FetchLimit.DECODED_SIZE, FetchLimit.PROBE_PREFIX)):
            raise ValueError("truncated には limit_hit（decoded_size / probe_prefix）が要ります")
        if o is FetchOutcome.TOO_LARGE and self.limit_hit is not FetchLimit.CONTENT_LENGTH:
            raise ValueError("too_large の limit_hit は content_length")
        if o is FetchOutcome.TIMEOUT and self.limit_hit not in (
            FetchLimit.CONNECT_TIMEOUT,
            FetchLimit.READ_TIMEOUT,
            FetchLimit.TOTAL_TIMEOUT,
        ):
            raise ValueError("timeout の limit_hit はタイムアウト系")
        if o is FetchOutcome.TOO_MANY_REDIRECTS:
            if self.limit_hit is not FetchLimit.REDIRECTS:
                raise ValueError("too_many_redirects の limit_hit は redirects")
            if not self.redirects or self.redirects[-1].followed:
                raise ValueError("too_many_redirects は、追跡しなかった最後の転送を持ちます")
        return self

    @property
    def has_audit_app_header(self) -> bool:
        """アプリ固有ヘッダ X-Audit-App の有無。429/503 を TRANSIENT にするか不適合にするかの境（§4）。"""
        return "x-audit-app" in self.headers

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@runtime_checkable
class FetchPort(Protocol):
    """外向き HTTP の唯一の出口（§2）。S1 はプロセス内の SafeFetch、S2 は S3（fetcher）へのクライアント。

    実装は T3。agent 側で requests/httpx/aiohttp を直接使うことは tests で禁止される。
    """

    async def fetch(self, request: FetchRequest) -> FetchResult: ...


# ---------------------------------------------------------------------------
# 検査の観測（§3・§4。tools / チェッカーが作り、Planner の StateView・判定表が読む）
# ---------------------------------------------------------------------------
def _fact_text(v: str) -> str:
    if "//" in v:  # "/login" のようなパスは許すが、URL（https://…）は載せられない
        raise ValueError("facts に URL は載せられません（パスは // を含まない形だけ）")
    return v


# facts の文字列は短い識別子と、スラッシュ区切りのパス断片（例 "/login"。証拠チップ「302→/login」の材料）だけ。
ObsValue = bool | int | Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9_.:/\-]{0,64}$"), AfterValidator(_fact_text)
]


class Observation(_Frozen):
    """コード整形の観測1件（例 `OBS{status:302, auth_wall:true}`）。判定表は outcome と strong で判定する。

    facts は bool / int / 短い識別子だけ。ページ本文のテキストは持てない（§4 http_probe）。
    """

    obs_id: ObsId
    tool: ToolName
    checker: Checker | None = None
    req_id: ReqId | None = None
    doc_id: DocId | None = None
    code: ObsCode
    outcome: ObsOutcome
    strong: bool = False  # OBS強（機械検証に足りる）。contains_terms の命中は弱
    facts: dict[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")], ObsValue] = Field(
        default_factory=dict, max_length=16
    )
    event_seq: int | None = Field(default=None, ge=0)  # 証拠チップのジャンプ先（TraceEvent.seq）

    @model_validator(mode="after")
    def _strong_means_conclusive(self) -> "Observation":
        if self.strong and self.outcome is ObsOutcome.INCONCLUSIVE:
            raise ValueError("不確定な観測を OBS強 にはできません")
        return self


# ---------------------------------------------------------------------------
# Planner が見る StateView（§3。約3KB。自由文を持たない）
# ---------------------------------------------------------------------------
class StateRequirement(_Frozen):
    """StateView の要件1行。引用・言い換え・要件の自由文は載せない（§2 Planner は見ない）。"""

    req_id: ReqId
    kind: Kind
    check_class: CheckClass
    state: ReqState = ReqState.OPEN
    routes: tuple[RouteId, ...] = Field(default=(), max_length=8)  # routes 候補（T8 の表の ID）
    calls_used: int = Field(default=0, ge=0, le=3)  # 要件ごとのツール呼び出し（最大3）


class StateDoc(_Frozen):
    """StateView の文書1行。本文は載せず、page_class・truncated・コード算出の DocFeatures だけ。"""

    doc_id: DocId
    role: DocRole
    page_class: PageClass
    truncated: bool = False
    features: DocFeatures


class StateLink(_Frozen):
    """リンク表の行。アンカー文言・URL は載せない（role とスコープ内外だけ）。"""

    link_id: LinkId
    role: LinkRole
    in_scope: bool
    fetched: bool = False


class StateView(_Frozen):
    """Planner が毎ターン見る唯一の入力（約3KB。履歴は持たない）。コードが毎ターン再構成する。

    生テキスト・summary・リンクのアンカー文言・注入フラグを持てない型にしてある
    （注入フラグを見て「信用しない文書は検査しない」と判断すると不適合が洗浄される＝S-03）。
    """

    turn: int = Field(ge=1)
    max_turns: int = Field(ge=1)
    allowed_tools: tuple[ToolName, ...]  # このターンに Governor が許可した関数名
    requirements: tuple[StateRequirement, ...]
    docs: tuple[StateDoc, ...]
    links: tuple[StateLink, ...] = ()
    budget: BudgetSnapshot
    last_observation: ObsCode | None = None
    # 直前の関数呼び出しが拒否された時の理由と関数名（許可されると消える）。同じ呼び出しの繰り返しを避けさせるための1語
    last_denial: DenialCode | None = None
    last_denied_tool: ToolName | None = None

    def to_prompt_json(self) -> str:
        """Planner へ渡す JSON。決定論的（キー順固定）。トレースの state_view にも同じものを残す。"""
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def size_bytes(self) -> int:
        return len(self.to_prompt_json().encode("utf-8"))


# ---------------------------------------------------------------------------
# トレース（§7。イベントは1種類に一本化）
# ---------------------------------------------------------------------------
class QuoteStep(_Frozen):
    """quote_check イベントの1ステップ。「言い換え→棄却→再引用→合格／推測へ降格」の連続を1本で残す（§5-1）。

    attempt は1（最初の引用）か2（再引用）。降格は2回目の棄却の後に attempt=2 の demoted として足す。
    model_quote は非信頼のモデル出力なので、T5 が textsafe.escape_for_display(quote, 160) を通してから載せる
    （ゼロ幅・bidi・タグ文字を \\u{..} 表記にし、160字で切る。そのまま入れると契約違反で ValidationError）。
    """

    attempt: int = Field(ge=1, le=2)
    outcome: QuoteStepOutcome
    reason_code: Token | None = None  # 棄却は QuoteRejectReason、降格は DemotionReason の値
    model_quote: Display160 | None = None  # 棄却された引用。textContent で描く
    quote_digest: Digest

    @model_validator(mode="after")
    def _reason(self) -> "QuoteStep":
        if self.outcome is not QuoteStepOutcome.VERIFIED and self.reason_code is None:
            raise ValueError("棄却・降格には理由コードが要ります")
        return self


class TraceEvent(_Frozen):
    """トレースイベント。SSE・Cloud Logging・Firestore・UI・リプレイが同じ列を使う（§7）。

    記録しないもの: ページ全文・プロンプト全文・モデルの生出力全文・生IP・トークン。
    自由文のフィールドを持たない（例外は ErrorCode だけ。str(e) は載せない）。state_view だけ約3KBの全文を載せる。
    """

    run_id: RunId
    seq: int = Field(ge=0)
    t_ms: int = Field(ge=0)
    phase: Phase
    actor: Actor
    type: TraceType
    name: Token | None = None  # ツール名・フェーズ名・モデル目的など
    req_id: ReqId | None = None
    obs_id: ObsId | None = None
    policy_id: PolicyId | None = None
    decision: Decision | None = None
    reason_code: Token | None = None
    args_digest: Digest | None = None
    result_digest: Digest | None = None
    tokens_in: int | None = Field(default=None, ge=0)
    tokens_out: int | None = Field(default=None, ge=0)
    est_cost_micro_jpy: int | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)
    flags: tuple[Token, ...] = Field(default=(), max_length=8)
    # 種別固有
    model: Token | None = None  # model_call
    purpose: ModelPurpose | None = None  # model_call
    finish_reason: Token | None = None  # model_call
    state_view: StateView | None = None  # state_view
    quote_steps: tuple[QuoteStep, ...] = Field(default=(), max_length=4)  # quote_check
    injection: InjectionSignal | None = None  # injection_signal
    verdict: VerdictLabel | None = None  # verdict（req_id と組。日本語の判定名は Token に載らないので専用欄）
    budget: BudgetSnapshot | None = None  # budget_snapshot
    attrs: dict[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")], ObsValue] = Field(
        default_factory=dict, max_length=12
    )
    bytes: int | None = Field(default=None, ge=0)  # 取得・本文のバイト数

    @model_validator(mode="after")
    def _by_type(self) -> "TraceEvent":
        t = self.type
        if t is TraceType.POLICY_DECISION:
            if self.policy_id is None or self.decision is None:
                raise ValueError("policy_decision には policy_id と decision が要ります")
        if self.decision is Decision.DENY and (self.policy_id is None or self.reason_code is None):
            raise ValueError("拒否は必ず policy_id と理由コードを出す（§4）")
        if t is TraceType.MODEL_CALL and (self.model is None or self.purpose is None):
            raise ValueError("model_call には model と purpose が要ります")
        if (t is TraceType.STATE_VIEW) != (self.state_view is not None):
            raise ValueError("state_view は state_view イベントにだけ載せる")
        if (t is TraceType.QUOTE_CHECK) != bool(self.quote_steps):
            raise ValueError("quote_steps は quote_check イベントにだけ載せる")
        if (t is TraceType.INJECTION_SIGNAL) != (self.injection is not None):
            raise ValueError("injection は injection_signal イベントにだけ載せる")
        if (t is TraceType.VERDICT) != (self.verdict is not None):
            raise ValueError("verdict は verdict イベントにだけ載せる（verdict イベントには必ず付ける）")
        if t is TraceType.VERDICT and self.req_id is None:
            raise ValueError("verdict イベントには req_id が要ります")
        if (t is TraceType.BUDGET_SNAPSHOT) != (self.budget is not None):
            raise ValueError("budget は budget_snapshot イベントにだけ載せる")
        return self

    def json_size(self) -> int:
        """JSON にした時のバイト数（MAX_EVENT_BYTES との比較用。state_view だけ例外）。"""
        return len(self.model_dump_json(exclude_none=True).encode("utf-8"))


# ---------------------------------------------------------------------------
# 判定・矛盾・実行記録（§3 判定表・§5-1・§7）
# ---------------------------------------------------------------------------
class EvidenceRef(_Frozen):
    """判定の証拠チップ。クリックで該当イベントへジャンプする（§7）。ラベルはコードが観測から組む。"""

    obs_id: ObsId
    event_seq: int | None = Field(default=None, ge=0)
    label: Display60  # 例「302→/login・password欄あり」


class Verdict(_Frozen):
    """判定表（adjudicate.py）の出力。モデルは判定を書けない。reason はコードのテンプレ文（140字以内）。

    不変条件: 確認不能だけが理由コードを持つ／適合・推定適合・不適合は証拠を1つ以上持つ。
    """

    req_id: ReqId
    label: VerdictLabel
    reason_code: UnverifiableReason | None = None
    reason: Reason140 = ""
    evidence: tuple[EvidenceRef, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def _invariants(self) -> "Verdict":
        if (self.label is VerdictLabel.UNVERIFIABLE) != (self.reason_code is not None):
            raise ValueError("理由コードを持つのは確認不能だけ（確認不能には必ず付ける）")
        if self.label in (VerdictLabel.PASS, VerdictLabel.PRESUMED_PASS, VerdictLabel.FAIL) and not self.evidence:
            raise ValueError("適合・推定適合・不適合には証拠が要ります")
        return self


class Contradiction(_Frozen):
    """要項間の矛盾（§5-1）。コードが決め、2つの検証済み引用の対で出す。判定表の外で別集計。"""

    slot: Slot
    req_ids: tuple[ReqId, ReqId]
    basis: ContradictionBasis
    tokens: tuple[Display40, Display40]  # 相違した日付・数値・属性語

    @model_validator(mode="after")
    def _pair(self) -> "Contradiction":
        if self.req_ids[0] == self.req_ids[1]:
            raise ValueError("矛盾は異なる2要件の対")
        if self.slot is Slot.NONE:
            raise ValueError("slot が無い対は矛盾に採用しません")
        return self


class UnverifiableMark(_Frozen):
    """要件を理由コードつきの「確認不能」に確定した記録（判定表への入力。§4 mark_unverifiable・§3 DEGRADED）。

    Planner の mark_unverifiable（P-UNVERIF-01 を通ったもの）と、コードが未決の要件へ付ける確認不能
    （予算切れ BUDGET・根拠なし NO_EVIDENCE・打切り TRUNCATED など）の両方を同じ形で持つ。
    premise_obs_id は前提の観測（NEEDS_AUTH は auth_wall の OBS、NEEDS_JS は spa_shell の OBS）。
    """

    req_id: ReqId
    reason_code: UnverifiableReason
    premise_obs_id: ObsId | None = None
    by_planner: bool = False  # Planner が確定した（False ならコードが確定）


class AdjudicationInput(_Frozen):
    """判定表（adjudicate.py）の入力。T9 が読み、T8（Planner ループ）・REPORT が組み立てる。

    モデルの自由文を含まない（要件は検証済みのものだけ、観測と印は列挙・数値だけ）。
    判定表は（要件の kind・check_class）×（その req_id の観測・文書の truncated / page_class）×（印）から
    要件ごとに Verdict を1つ返す。観測は run_check が req_id 付きで返す（CHECK_CLASS_CHECKER の checker）。
    """

    requirements: tuple[VerifiedRequirement, ...]
    docs: tuple[DocMeta, ...] = ()
    observations: tuple[Observation, ...] = ()
    marks: tuple[UnverifiableMark, ...] = ()

    @model_validator(mode="after")
    def _refs(self) -> "AdjudicationInput":
        req_ids = {r.req_id for r in self.requirements}
        if len(req_ids) != len(self.requirements):
            raise ValueError("req_id が重複しています")
        doc_ids = {d.doc_id for d in self.docs}
        obs_ids = [o.obs_id for o in self.observations]
        if len(set(obs_ids)) != len(obs_ids):
            raise ValueError("obs_id が重複しています")
        for o in self.observations:
            if o.req_id is not None and o.req_id not in req_ids:
                raise ValueError("観測が存在しない要件を指しています")
            if o.doc_id is not None and o.doc_id not in doc_ids:
                raise ValueError("観測が docs に無い文書を指しています")
        mark_ids = [m.req_id for m in self.marks]
        if len(set(mark_ids)) != len(mark_ids):
            raise ValueError("1要件に確認不能の印が複数あります")
        recorded = set(obs_ids)
        for m in self.marks:
            if m.req_id not in req_ids:
                raise ValueError("確認不能の印が存在しない要件を指しています")
            if m.premise_obs_id is not None and m.premise_obs_id not in recorded:
                raise ValueError("確認不能の前提の観測が見つかりません")
        return self


class RunSummary(_Frozen):
    """サマリ帯の数値（§8 UI・§3 J8）。「引用検証 N件中M件が逐語一致・K件を推測へ降格」などを作る元。"""

    requirements_total: int = Field(ge=0)
    obligatory_total: int = Field(ge=0)  # 必須・禁止
    capped: bool = False  # 要件上限で打切りあり
    quotes_checked: int = Field(ge=0)  # N
    quotes_verbatim: int = Field(ge=0)  # M（逐語一致した引用）
    demoted_to_speculative: int = Field(ge=0)  # K
    verdict_counts: dict[VerdictLabel, int] = Field(default_factory=dict)
    contradictions: int = Field(ge=0)
    injection_visible: int = Field(ge=0)
    injection_hidden: int = Field(ge=0)
    denied: int = Field(ge=0)  # Governor の拒否件数
    quote_rejected: int = Field(ge=0)  # 引用棄却のステップ数
    est_cost_micro_jpy: int = Field(ge=0)

    @classmethod
    def compute(
        cls,
        requirements: Sequence["VerifiedRequirement"],
        verdicts: Sequence[Verdict],
        contradictions: Sequence[Contradiction],
        injection_signals: Sequence[InjectionSignal],
        events: Sequence[TraceEvent],
        *,
        capped: bool = False,
    ) -> "RunSummary":
        counts: dict[VerdictLabel, int] = {}
        for v in verdicts:
            counts[v.label] = counts.get(v.label, 0) + 1
        return cls(
            requirements_total=len(requirements),
            obligatory_total=sum(1 for r in requirements if r.kind in OBLIGATORY_KINDS),
            capped=capped,
            quotes_checked=len(requirements),
            quotes_verbatim=sum(1 for r in requirements if r.span is not None),
            # 「K件を推測へ降格」＝申告が推測でなかったものが推測になった件数（最初から推測の申告は数えない）
            demoted_to_speculative=sum(
                1
                for r in requirements
                if r.demotion is not None and r.kind is Kind.SPECULATIVE and r.declared_kind is not Kind.SPECULATIVE
            ),
            verdict_counts=counts,
            contradictions=len(contradictions),
            injection_visible=sum(1 for s in injection_signals if s.visible),
            injection_hidden=sum(1 for s in injection_signals if not s.visible),
            denied=sum(1 for e in events if e.decision is Decision.DENY),
            quote_rejected=sum(
                1 for e in events for st in e.quote_steps if st.outcome is QuoteStepOutcome.REJECTED
            ),
            est_cost_micro_jpy=sum(e.est_cost_micro_jpy or 0 for e in events),
        )


class RunRecord(_Frozen):
    """1実行の記録（REPORT が作り、PERSIST が Firestore へ、UI とリプレイが読む。§3・§7）。

    ページ全文・プロンプト全文・生IPは持たない。requirements は VerifiedRequirement だけ。
    VerifiedRequirement は seal が要るので、JSON から戻すには restore_json を使う。
    """

    run_id: RunId
    env: EnvName
    mode: RunMode
    status: RunStatus
    degraded_reason: DegradedReason | None = None  # status=DEGRADED の時だけ（必須）
    aborted_reason: AbortReason | None = None  # status=ABORTED の時だけ（必須）
    preset_id: PresetId
    prompt_version: Token
    reader_model: Token
    planner_model: Token
    started_at: AwareDatetime
    docs: tuple[DocMeta, ...] = ()
    requirements: tuple[VerifiedRequirement, ...] = ()
    verdicts: tuple[Verdict, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    injection_signals: tuple[InjectionSignal, ...] = ()
    observations: tuple[Observation, ...] = Field(default=(), max_length=64)  # 判定の証拠（EvidenceRef.obs_id の参照先）
    summary: RunSummary
    budget: BudgetSnapshot
    events: tuple[TraceEvent, ...] = Field(default=(), max_length=MAX_EVENTS_PER_RUN)
    omitted_events: int = Field(default=0, ge=0)  # 間引いたイベント数（「省略N件」表示用。§7）
    omitted_requirements: int = Field(default=0, ge=0)  # 同梱の REPLAY が件数上限で省いた要件の数（件数だけ残す。summary は元の実行の値）
    public: bool = False  # 採録した録画元（GET が run_id 無しで返してよい）

    @model_validator(mode="after")
    def _consistent(self) -> "RunRecord":
        if (self.status is RunStatus.DEGRADED) != (self.degraded_reason is not None):
            raise ValueError("degraded_reason は status=DEGRADED の時だけ、かつ必ず付ける")
        if (self.status is RunStatus.ABORTED) != (self.aborted_reason is not None):
            raise ValueError("aborted_reason は status=ABORTED の時だけ、かつ必ず付ける")
        req_by_id = {r.req_id: r for r in self.requirements}
        if len(req_by_id) != len(self.requirements):
            raise ValueError("req_id が重複しています")
        doc_ids = {d.doc_id for d in self.docs}
        if len(doc_ids) != len(self.docs):
            raise ValueError("doc_id が重複しています")
        for r in self.requirements:
            if r.span is not None and r.span.doc_id not in doc_ids:
                raise ValueError("要件の出典 doc_id が docs にありません")
        verdict_ids = [v.req_id for v in self.verdicts]
        if len(set(verdict_ids)) != len(verdict_ids):
            raise ValueError("1要件に判定が複数あります")
        for v in self.verdicts:
            r = req_by_id.get(v.req_id)
            if r is None:
                raise ValueError("判定が存在しない要件を指しています")
            if (r.kind is Kind.SPECULATIVE) != (v.label is VerdictLabel.REFERENCE):
                raise ValueError("参考は推測 kind だけの判定です（推測は必ず参考）")
        obs_ids = [o.obs_id for o in self.observations]
        if len(set(obs_ids)) != len(obs_ids):
            raise ValueError("obs_id が重複しています")
        for o in self.observations:
            if (o.req_id is not None and o.req_id not in req_by_id) or (o.doc_id is not None and o.doc_id not in doc_ids):
                raise ValueError("観測が存在しない要件・文書を指しています")
        recorded = set(obs_ids)
        for v in self.verdicts:
            for ev in v.evidence:
                if ev.obs_id not in recorded:
                    raise ValueError("判定の証拠が observations に無い観測を指しています")
        for c in self.contradictions:
            a, b = (req_by_id.get(i) for i in c.req_ids)
            if a is None or b is None or a.span is None or b.span is None:
                raise ValueError("矛盾は検証済みの2引用の対だけ")
            if a.span.doc_id == b.span.doc_id:
                raise ValueError("矛盾は異なる文書の対だけ")
            if a.slot is not c.slot or b.slot is not c.slot:
                raise ValueError("矛盾の slot が2要件と一致しません")
        last = -1
        for e in self.events:
            if e.run_id != self.run_id:
                raise ValueError("別の実行のイベントが混ざっています")
            if e.seq <= last:
                raise ValueError("イベントの seq は単調増加")
            last = e.seq
        return self

    @model_validator(mode="after")
    def _all_verdicts(self) -> "RunRecord":
        """完了・降格の実行では全要件に判定が要る（要項モードの SpecOnlyRecord はこの検査を「判定を持たない」に差し替える）。"""
        if self.status is not RunStatus.ABORTED and {v.req_id for v in self.verdicts} != {r.req_id for r in self.requirements}:
            raise ValueError("完了・降格の実行では全要件に判定が要ります（未検査は理由コードつきの確認不能）")
        return self

    @classmethod
    def restore(cls, data: Mapping[str, Any], *, seal: VerificationSeal) -> "RunRecord":
        d = dict(data)
        d["requirements"] = tuple(VerifiedRequirement.restore(r, seal=seal) for r in d.get("requirements", ()))
        return cls.model_validate(d)

    @classmethod
    def restore_json(cls, text: str | bytes, *, seal: VerificationSeal) -> "RunRecord":
        return cls.restore(json.loads(text), seal=seal)


class SpecOnlyRecord(RunRecord):
    """要項モード（第11弾）の結果: 要件の一覧だけ。判定・観測・矛盾を持たないことを型で表す（kind="spec_only"）。

    RunRecord の欄をそのまま使い（requirements・docs・summary・budget・events）、検査・判定の欄は空でなければ作れない。
    画面は `kind === "spec_only"` で通常の結果と分ける。判定を書けるのは adjudicate.py だけという規則はそのまま（ここは判定を作らない）。
    """

    kind: Literal["spec_only"] = "spec_only"
    preset_id: Literal["spec_url"] = SPEC_URL_PRESET_ID

    @model_validator(mode="after")
    def _all_verdicts(self) -> "SpecOnlyRecord":  # RunRecord の同名の検査を差し替える
        if self.verdicts or self.observations or self.contradictions:
            raise ValueError("要項モードの結果は判定・観測・矛盾を持てません")
        if self.summary.verdict_counts:
            raise ValueError("要項モードの集計に判定の件数は載せません")
        return self


def serialize_requirements(items: Iterable[object]) -> list[dict[str, Any]]:
    """REPORT / UI 用。VerifiedRequirement 以外（RawRequirement など）が混ざると例外（§5-1 型分離）。"""
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, VerifiedRequirement):
            raise UnverifiedSerializationError(f"未検証の型はシリアライズできません: {type(it).__name__}")
        out.append(it.model_dump(mode="json"))
    return out


def serialize_report(record: RunRecord) -> str:
    """RunRecord を JSON 文字列にする唯一の入口。model_construct で検証を迂回した記録もここで弾く。"""
    if not isinstance(record, RunRecord):
        raise UnverifiedSerializationError("RunRecord 以外はシリアライズできません")
    serialize_requirements(record.requirements)
    return record.model_dump_json()


# ---------------------------------------------------------------------------
# ツール呼び出し（§4。Planner の関数呼び出しを型にする。Governor・ToolRegistry・ScriptedPort が共有）
# ---------------------------------------------------------------------------
ProbeTarget = Annotated[str, StringConstraints(pattern=r"^(SUBMISSION_URL|L[0-9]{1,3})$")]


class FetchLinkArgs(_Frozen):
    """fetch_link(link_id, reason)。URL 文字列を渡せない（ID 参照）。"""

    link_id: LinkId
    reason: Reason140 = Field(min_length=1)


class HttpProbeArgs(_Frozen):
    """http_probe(target, reason)。target は SUBMISSION_URL（プリセット定数）か link_id だけ。"""

    target: ProbeTarget
    reason: Reason140 = Field(min_length=1)


class RunCheckArgs(_Frozen):
    """run_check(checker, req_id)。パラメータは引数で受けず、検証済み引用由来の値だけをチェッカーが使う。"""

    checker: Checker
    req_id: ReqId


class MarkUnverifiableArgs(_Frozen):
    """mark_unverifiable(req_id, reason_code)。許可は P-UNVERIF-01（routes の allowed_codes と前提 OBS）。"""

    req_id: ReqId
    reason_code: UnverifiableReason


class FinishArgs(_Frozen):
    """finish()。引数なし。"""


TOOL_ARG_MODELS: dict[ToolName, type[BaseModel]] = {
    ToolName.FETCH_LINK: FetchLinkArgs,
    ToolName.HTTP_PROBE: HttpProbeArgs,
    ToolName.RUN_CHECK: RunCheckArgs,
    ToolName.MARK_UNVERIFIABLE: MarkUnverifiableArgs,
    ToolName.FINISH: FinishArgs,
}


class ToolCall(_Frozen):
    """検証済みのツール呼び出し。parse_tool_call だけが作る想定（name と args の型が対応していること）。"""

    name: ToolName
    args: FetchLinkArgs | HttpProbeArgs | RunCheckArgs | MarkUnverifiableArgs | FinishArgs

    @model_validator(mode="after")
    def _match(self) -> "ToolCall":
        if type(self.args) is not TOOL_ARG_MODELS[self.name]:
            raise ValueError("name と args の型が対応していません")
        return self


class FunctionCall(_Frozen):
    """モデルが返した関数呼び出し（生）。名前も引数も非信頼で、Governor が parse_tool_call で検証する。"""

    name: str = Field(max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)


def parse_tool_call(name: str, args: Mapping[str, Any]) -> ToolCall:
    """生の関数呼び出し → ToolCall。許可リスト外の名前・未知の引数・型違いは AppError(INVALID_INPUT)。"""
    try:
        tool = ToolName(name)
    except ValueError:
        raise AppError(ErrorCode.INVALID_INPUT, f"未知のツール名: {name[:40]!r}") from None
    try:
        parsed = TOOL_ARG_MODELS[tool].model_validate(dict(args))
        return ToolCall(name=tool, args=parsed)  # type: ignore[arg-type]
    except ValidationError as e:
        raise AppError(ErrorCode.INVALID_INPUT, f"引数が不正: {tool.value}: {e.error_count()}件") from e


# ---------------------------------------------------------------------------
# モデル呼び出し（ModelPort の入出力。実装は app/model/）
# ---------------------------------------------------------------------------
def llm_json_schema(model: type[BaseModel]) -> dict[str, Any]:
    """pydantic モデル → モデルへ渡す JSON Schema。

    $ref を展開し、title / default / additionalProperties / description / maxItems を除く。
    description を除くのは、クラスの docstring（設計メモ）がそのままモデルへ渡るのを防ぐため。
    """
    schema = model.model_json_schema()
    defs: dict[str, Any] = schema.pop("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(x) for x in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node:
            return walk(defs[node["$ref"].rsplit("/", 1)[-1]])
        out: dict[str, Any] = {}
        for k, v in node.items():
            if k in ("title", "default", "additionalProperties", "description", "maxItems"):
                continue  # maxItems: Vertex(gemini-3.7-flash)が400で拒否する（2026-10-06実測）。上限は受信後の pydantic 検証が守る
            if k == "properties":  # プロパティ名は絞り込まない
                out[k] = {pk: walk(pv) for pk, pv in v.items()}
            else:
                out[k] = walk(v)
        return out

    return walk(schema)  # type: ignore[no-any-return]


class ToolDecl(_Frozen):
    """モデルへ渡す関数宣言（Planner のツール）。引数のスキーマは TOOL_ARG_MODELS から作る。"""

    name: ToolName
    description: str = Field(max_length=500)
    parameters: dict[str, Any]

    @classmethod
    def for_tool(cls, name: ToolName, description: str) -> "ToolDecl":
        return cls(name=name, description=description, parameters=llm_json_schema(TOOL_ARG_MODELS[name]))


class ModelRequest(_Frozen):
    """ModelPort への1回の呼び出し要求。Reader と Planner の分離を型で守る。

    Reader（response_model あり・ツール無し）は生テキストを読む。Planner（ツールあり・response_model 無し）は
    StateView だけを読む。両方を同時に持つ呼び出しは作れない（§2「ツールと生テキストを同時に持たない」）。
    型が強制するのは「分離」（Reader はツール不可・Planner は schema 不可）まで。Reader が response_schema を必ず付ける
    ことは Reader モジュール（T6）が守る（ops/measure_gemini.py は実測のために schema 無しの Reader 目的の呼び出しを作る）。
    contents は非信頼テキストを含みうるので repr に出さず、ログには request_digest だけを残す。
    """

    purpose: ModelPurpose
    system: str = Field(repr=False)
    contents: str = Field(repr=False)
    response_model: type[BaseModel] | None = None
    tools: tuple[ToolDecl, ...] = ()
    allowed_tool_names: tuple[ToolName, ...] = ()  # Governor がターン毎に決める許可関数名（§2）
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: int = Field(gt=0)
    thinking_budget: int | None = Field(default=None, ge=0)
    timeout_s: float = Field(gt=0)

    @model_validator(mode="after")
    def _separation(self) -> "ModelRequest":
        if self.purpose is ModelPurpose.READER and (self.tools or self.allowed_tool_names):
            raise ValueError("Reader はツールを持てません")
        if self.purpose is ModelPurpose.PLANNER:
            if self.response_model is not None:
                raise ValueError("Planner は関数呼び出しのみ（response_model を持てません）")
            if not self.tools or not self.allowed_tool_names:
                raise ValueError("Planner にはツール宣言と許可関数名が要ります")
        declared = {t.name for t in self.tools}
        if not set(self.allowed_tool_names) <= declared:
            raise ValueError("許可関数名が宣言に無いツールを含みます")
        return self

    def request_digest(self) -> str:
        """cassette・ログ用の決定論的ダイジェスト（sha256 の16進）。プロンプト本文はログへ出さずこれだけを使う。"""
        payload = {
            "purpose": self.purpose.value,
            "system": self.system,
            "contents": self.contents,
            "response_schema": llm_json_schema(self.response_model) if self.response_model else None,
            "tools": [t.model_dump(mode="json") for t in self.tools],
            "allowed": [n.value for n in self.allowed_tool_names],
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "thinking_budget": self.thinking_budget,
        }
        blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Usage(_Frozen):
    """1回の呼び出しのトークン使用量（usage_metadata の写し）。課金に効く定義はここに固定する（§6-1）。

    tokens_out = candidates + thoughts（+ tool_use 分）。既存 `/probe` は thoughts を数えないので流用しない。
    """

    prompt_tokens: int = Field(default=0, ge=0)
    candidates_tokens: int = Field(default=0, ge=0)
    thoughts_tokens: int = Field(default=0, ge=0)
    tool_use_prompt_tokens: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)

    @property
    def tokens_in(self) -> int:
        return self.prompt_tokens

    @property
    def tokens_out(self) -> int:
        return self.candidates_tokens + self.thoughts_tokens + self.tool_use_prompt_tokens


class ModelResponse(_Frozen):
    """ModelPort の戻り。text は JSON（Reader）、function_calls は Planner の関数呼び出し（生）。"""

    model: Token
    text: str | None = Field(default=None, repr=False)
    function_calls: tuple[FunctionCall, ...] = ()
    usage: Usage = Field(default_factory=Usage)
    finish_reason: Token | None = None
    latency_ms: int = Field(default=0, ge=0)

