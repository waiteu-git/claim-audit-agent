"""errors.py: 分類・公開メッセージ・非公開詳細の分離。"""
import asyncio
import json

import pytest
from google.genai import errors as genai_errors
from pydantic import BaseModel, ValidationError

from app.errors import PUBLIC_MESSAGES, AppError, ErrorCode, PublicError, classify, is_retryable


def _api(cls, code):
    return cls(code, {"error": {"message": "private detail", "status": "X"}})


@pytest.mark.parametrize(
    "exc,expected",
    [
        (_api(genai_errors.ServerError, 500), ErrorCode.RETRYABLE),
        (_api(genai_errors.ServerError, 503), ErrorCode.RETRYABLE),
        (_api(genai_errors.ClientError, 429), ErrorCode.RETRYABLE),
        (_api(genai_errors.ClientError, 408), ErrorCode.RETRYABLE),
        (_api(genai_errors.ClientError, 400), ErrorCode.FATAL_CONFIG),
        (_api(genai_errors.ClientError, 401), ErrorCode.FATAL_CONFIG),
        (_api(genai_errors.ClientError, 403), ErrorCode.FATAL_CONFIG),
        (_api(genai_errors.ClientError, 404), ErrorCode.FATAL_CONFIG),
        (_api(genai_errors.ClientError, 418), ErrorCode.FATAL_CONFIG),  # 不明な 4xx は開けない側
        (TimeoutError(), ErrorCode.RETRYABLE),
        (asyncio.TimeoutError(), ErrorCode.RETRYABLE),
        (ConnectionResetError(), ErrorCode.RETRYABLE),
        (OSError("boom"), ErrorCode.RETRYABLE),
        (asyncio.CancelledError(), ErrorCode.CANCELLED),
        (json.JSONDecodeError("x", "y", 0), ErrorCode.SCHEMA_VIOLATION),
        (ValueError("x"), ErrorCode.INTERNAL),
        (RuntimeError("x"), ErrorCode.INTERNAL),
        (AppError(ErrorCode.QUOTA), ErrorCode.QUOTA),
        (AppError(ErrorCode.KILLED, "kill"), ErrorCode.KILLED),
    ],
)
def test_classify(exc, expected):
    assert classify(exc) is expected


def test_classify_pydantic_validation_error():
    class M(BaseModel):
        x: int

    with pytest.raises(ValidationError) as ei:
        M(x="not-int")
    assert classify(ei.value) is ErrorCode.SCHEMA_VIOLATION


def test_classify_duck_types_http_like_exceptions_without_importing_sdks():
    class FakeHttpError(Exception):
        status_code = 404

    class FakeWrapped(Exception):
        class response:  # noqa: N801
            status_code = 503

    assert classify(FakeHttpError()) is ErrorCode.FATAL_CONFIG
    assert classify(FakeWrapped()) is ErrorCode.RETRYABLE
    bool_code = type("E", (Exception,), {"code": True})()
    assert classify(bool_code) is ErrorCode.INTERNAL  # bool を HTTP コードと誤認しない


def test_only_retryable_is_retryable():
    assert [c for c in ErrorCode if is_retryable(c)] == [ErrorCode.RETRYABLE]


def test_every_code_has_a_fixed_japanese_public_message():
    assert set(PUBLIC_MESSAGES) == set(ErrorCode)
    for msg in PUBLIC_MESSAGES.values():
        assert msg and msg.endswith("。")
        assert not any(c.isdigit() for c in msg), "公開メッセージに値（数字・ID）を埋め込まない"
        assert "http" not in msg.lower() and "/" not in msg


def test_public_message_never_contains_the_private_detail():
    e = AppError(ErrorCode.FETCH_FAILED, "https://secret.internal/path?token=abc")
    assert "secret" not in e.public_message and "token" not in e.public_message
    assert "secret" in str(e)  # 非公開ログ用には残る
    assert e.detail.startswith("https://")
    assert AppError(ErrorCode.INTERNAL).args[0] == "INTERNAL"


def test_public_error_shape_is_closed():
    pe = PublicError.from_code(ErrorCode.QUOTA)
    assert pe.model_dump() == {"code": ErrorCode.QUOTA, "message": PUBLIC_MESSAGES[ErrorCode.QUOTA]}
    with pytest.raises(ValidationError):
        PublicError(code=ErrorCode.QUOTA, message="x", detail="traceback")  # type: ignore[call-arg]
