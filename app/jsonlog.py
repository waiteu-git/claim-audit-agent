"""構造化ログ（設計 §7）。stdout に JSON 1行/イベント。Cloud Run が severity / message を解釈する。

出さないもの: 生IP・ページ全文・プロンプト全文・秘密。キーの拒否リストと IPv4 の伏せ字で機械的に守る。
str(e)・traceback は非公開ログであるここにだけ書く（trace / SSE / Firestore へは ErrorCode だけ。errors.py）。
"""
import json
import logging
import re
import sys
import traceback
from datetime import UTC, datetime
from typing import IO, Any

from pydantic import BaseModel, ValidationError

from app.contracts import Decision, PolicyId, TraceEvent, TraceType
from app.errors import classify

LOGGER_NAME = "claim_audit"
_HANDLER_TAG = "_claim_audit_json_handler"

# 値を出さないキー（小文字・完全一致）。ページ本文・プロンプト・認証情報・生IPの系統。
FORBIDDEN_KEYS = frozenset(
    {
        "ip", "remote_ip", "client_ip", "remote_addr", "x_forwarded_for", "forwarded",
        "body", "text", "html", "page", "content", "visible_text", "prompt", "contents", "system",
        "authorization", "token", "id_token", "access_token", "cookie", "set_cookie",
        "password", "secret", "api_key", "judge_code", "x_judge",
    }
)  # fmt: skip
OMITTED = "[omitted]"
MAX_VALUE_CHARS = 500

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_SEVERITY = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}


def _scrub_str(v: str) -> str:
    v = _IPV4.sub("[ip]", v)
    if len(v) > MAX_VALUE_CHARS:
        v = f"{v[:MAX_VALUE_CHARS]}…(+{len(v) - MAX_VALUE_CHARS}字)"
    return v


def _scrub(value: Any, depth: int = 0) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, str):
        return _scrub_str(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 4:
        return OMITTED
    if isinstance(value, dict):
        return {
            str(k): (OMITTED if str(k).lower() in FORBIDDEN_KEYS else _scrub(v, depth + 1)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_scrub(v, depth + 1) for v in list(value)[:100]]
    return f"<{type(value).__name__}>"  # 任意オブジェクトの repr は出さない（本文・秘密を含みうる）


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, Any] = getattr(record, "fields", {})
        out: dict[str, Any] = {
            "severity": _SEVERITY.get(record.levelno, "DEFAULT"),
            "message": record.getMessage(),
            "event": record.getMessage(),
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
        }
        for k, v in fields.items():
            if k in out:  # 予約キーは上書きさせない
                k = f"field_{k}"
            out[k] = OMITTED if k.lower() in FORBIDDEN_KEYS else _scrub(v)
        return json.dumps(out, ensure_ascii=False, separators=(",", ":"))  # 改行は JSON が必ずエスケープする


def setup_logging(level: str = "INFO", stream: IO[str] | None = None) -> logging.Logger:
    """JSON ログを有効にする（何度呼んでも重複しない）。stream を渡せばテストで捕捉できる。"""
    logger = logging.getLogger(LOGGER_NAME)
    for h in [h for h in logger.handlers if getattr(h, _HANDLER_TAG, False)]:
        logger.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    setattr(handler, _HANDLER_TAG, True)
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False
    return logger


def log_event(event: str, *, severity: str = "INFO", **fields: Any) -> None:
    """1イベント1行。fields の値は伏せ字・切り詰め済みで出る。"""
    logging.getLogger(LOGGER_NAME).log(getattr(logging, severity.upper()), event, extra={"fields": fields})


def _safe_validation_detail(exc: ValidationError) -> str:
    """pydantic の検証失敗 → 「フィールド名: エラー種別」だけ。str(exc) は失敗した値の抜粋（input_value＝取得した本文の先頭など）を含む。"""
    errs = exc.errors(include_input=False, include_url=False, include_context=False)
    return "; ".join(f"{'.'.join(str(x) for x in e['loc'])}:{e['type']}" for e in errs)[:500]


def log_exception(event: str, exc: BaseException, **fields: Any) -> None:
    """例外を非公開ログへ。error_code だけが公開面へ出してよい値で、detail / traceback はここにだけ書く。

    ValidationError は値（input_value）を含む文面を持つので、detail と traceback の末尾にはフィールド名とエラー種別だけを書く。
    """
    if isinstance(exc, ValidationError):
        detail = _safe_validation_detail(exc)
        tb = "".join(traceback.format_tb(exc.__traceback__))[-2000:] + f"{type(exc).__name__}: {detail}"
    else:
        detail = str(exc)
        tb = "".join(traceback.format_exception(exc))[-2000:]
    log_event(
        event,
        severity="ERROR",
        error_code=classify(exc).value,
        error_type=type(exc).__name__,
        detail=detail,
        traceback=tb,
        **fields,
    )


def trace_severity(ev: TraceEvent) -> str:
    """guard 系は WARNING、kill / budget_stop は ERROR（§7）。"""
    if ev.policy_id is PolicyId.KILL or (ev.type is TraceType.ABORT and (ev.reason_code or "") in ("KILLED", "BUDGET")):
        return "ERROR"
    if ev.decision is Decision.DENY or ev.type in (TraceType.INJECTION_SIGNAL, TraceType.ABORT):
        return "WARNING"
    return "INFO"


def log_trace_event(ev: TraceEvent) -> None:
    log_event(f"trace.{ev.type.value}", severity=trace_severity(ev), **ev.model_dump(mode="json", exclude_none=True))
