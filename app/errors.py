"""エラーの型と、公開面に出してよいメッセージの区別（設計 §6-4・§7 S-05）。

規則: trace / SSE / Firestore / 画面へ出してよいのは ErrorCode と PUBLIC_MESSAGES の固定文だけ。
`str(e)`・`repr(e)`・traceback は非公開ログ（jsonlog）にだけ書く。自由文の error フィールドは作らない。
"""
import asyncio
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, ValidationError


class ErrorCode(StrEnum):
    # Vertex 例外の3分類（§6-4）
    RETRYABLE = "RETRYABLE"  # 429 / 5xx / タイムアウト / 一時的な通信断。再試行してよい
    QUOTA = "QUOTA"  # 自前の枠・予算の枯渇（quota.py / Budget）。再試行しない
    FATAL_CONFIG = "FATAL_CONFIG"  # 400 / 401 / 403 / 404。設定の誤り。即中断＋kill_live 自動 true
    # それ以外
    KILLED = "KILLED"  # キルスイッチ（L1/L2）
    CANCELLED = "CANCELLED"  # クライアント切断・75秒超過による中止
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"  # モデル出力が契約（pydantic）に合わない
    INVALID_INPUT = "INVALID_INPUT"  # 入力（プリセットID・ツール引数）が不正
    FETCH_BLOCKED = "FETCH_BLOCKED"  # SafeFetch がスコープ・SSRF 規則で拒否
    FETCH_FAILED = "FETCH_FAILED"  # 取得に失敗（接続・上限・種別）
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"  # Firestore 不達
    INTERNAL = "INTERNAL"  # 分類できない例外。不明なら開けない（fail-closed）


# 公開してよい固定文。値（URL・ID・数値）を埋め込まない＝漏洩の経路を作らない。
PUBLIC_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.RETRYABLE: "一時的な問題でモデルを呼び出せませんでした。",
    ErrorCode.QUOTA: "本日のライブ実行の枠を使い切りました。",
    ErrorCode.FATAL_CONFIG: "ライブ実行を一時的に停止しています。",
    ErrorCode.KILLED: "ライブ実行を停止しています。",
    ErrorCode.CANCELLED: "実行を中止しました。",
    ErrorCode.SCHEMA_VIOLATION: "モデルの出力が想定の形式ではありませんでした。",
    ErrorCode.INVALID_INPUT: "入力が正しくありません。",
    ErrorCode.FETCH_BLOCKED: "取得は許可された範囲の外のため行いませんでした。",
    ErrorCode.FETCH_FAILED: "ページを取得できませんでした。",
    ErrorCode.STORE_UNAVAILABLE: "記録の保存先に接続できませんでした。",
    ErrorCode.INTERNAL: "内部エラーが発生しました。",
}


class AppError(Exception):
    """アプリが意図して投げる例外。

    `code` と `public_message` だけが公開面に出てよい。`detail` は非公開ログ専用
    （str(e) も detail を返す＝公開面へ str(e) を渡さないこと）。
    """

    def __init__(self, code: ErrorCode, detail: str = "", *, retry_after_s: float | None = None) -> None:
        super().__init__(detail or code.value)
        self.code = code
        self.detail = detail
        self.retry_after_s = retry_after_s

    @property
    def public_message(self) -> str:
        return PUBLIC_MESSAGES[self.code]


class PublicError(BaseModel):
    """SSE / JSON 応答へ出してよいエラーの形。ErrorCode と固定文だけで、自由文を持てない。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ErrorCode
    message: str

    @classmethod
    def from_code(cls, code: ErrorCode) -> "PublicError":
        return cls(code=code, message=PUBLIC_MESSAGES[code])


def classify(e: BaseException) -> ErrorCode:
    """例外 → ErrorCode。trace / SSE / Firestore へ出してよいのはこの戻り値だけ。

    HTTP 風の例外は duck typing（`code` / `status_code` が int）で判定し、google-genai などへは import 依存しない。
    """
    if isinstance(e, AppError):
        return e.code
    if isinstance(e, asyncio.CancelledError):
        return ErrorCode.CANCELLED
    if isinstance(e, (ValidationError, json.JSONDecodeError)):
        return ErrorCode.SCHEMA_VIOLATION
    if isinstance(e, TimeoutError):  # asyncio.TimeoutError は 3.11+ で同一
        return ErrorCode.RETRYABLE
    status = _http_status(e)
    if status is not None:
        return _from_http_status(status)
    if isinstance(e, OSError):  # ConnectionError 等。一時的な通信断として扱う
        return ErrorCode.RETRYABLE
    return ErrorCode.INTERNAL


def _http_status(e: BaseException) -> int | None:
    for attr in ("code", "status_code"):
        v = getattr(e, attr, None)
        if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599:
            return v
    resp = getattr(e, "response", None)
    v = getattr(resp, "status_code", None)
    if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599:
        return v
    return None


def _from_http_status(status: int) -> ErrorCode:
    if status == 429 or status == 408 or status >= 500:
        return ErrorCode.RETRYABLE
    if 400 <= status < 500:
        return ErrorCode.FATAL_CONFIG  # 400/401/403/404 ほか。不明な 4xx も開けない側へ
    return ErrorCode.INTERNAL


def is_retryable(code: ErrorCode) -> bool:
    return code is ErrorCode.RETRYABLE
