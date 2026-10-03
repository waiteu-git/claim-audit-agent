"""構造化ログ: 1イベント1行・生IPとページ全文を出さない・例外は非公開ログにだけ。"""
import io
import json

import pytest
from google.genai import errors as genai_errors

import app.contracts as C
import app.jsonlog as jl
from tests.factories import make_event


@pytest.fixture
def buf():
    stream = io.StringIO()
    jl.setup_logging("DEBUG", stream)
    yield stream
    jl.logging.getLogger(jl.LOGGER_NAME).handlers.clear()


def lines(buf: io.StringIO) -> list[dict]:
    return [json.loads(x) for x in buf.getvalue().splitlines()]


def test_one_json_line_per_event_with_cloud_logging_fields(buf):
    jl.log_event("phase_enter", phase="ACQUIRE", n=3)
    jl.log_event("budget_stop", severity="error", dimension="model_calls")
    a, b = lines(buf)
    assert a["severity"] == "INFO" and a["message"] == "phase_enter" == a["event"] and a["phase"] == "ACQUIRE" and a["n"] == 3
    assert b["severity"] == "ERROR" and a["time"].endswith("+00:00")


def test_newlines_and_control_characters_cannot_split_a_log_line(buf):
    jl.log_event("x", note="line1\nline2\r\n{\"severity\":\"CRITICAL\"}")
    assert len(buf.getvalue().splitlines()) == 1
    assert lines(buf)[0]["severity"] == "INFO"


def test_forbidden_keys_never_carry_values(buf):
    jl.log_event("req", ip="203.0.113.7", client_ip="203.0.113.8", body="<html>全文</html>", visible_text="本文", prompt="命令", Authorization="Bearer x", judge_code="abc", X_Judge="abc")
    row = lines(buf)[0]
    for k in ("ip", "client_ip", "body", "visible_text", "prompt", "Authorization", "judge_code", "X_Judge"):
        assert row[k] == jl.OMITTED
    assert "203.0.113" not in buf.getvalue() and "全文" not in buf.getvalue()


def test_ip_addresses_inside_values_are_masked_but_versions_survive(buf):
    jl.log_event("x", msg="from 203.0.113.7 and 10.0.0.1:8080", ver="2026.10.02.1", rev="1.2.3")
    row = lines(buf)[0]
    assert row["msg"] == "from [ip] and [ip]:8080"
    assert row["ver"] == "2026.10.02.1" and row["rev"] == "1.2.3"


def test_long_values_are_truncated_with_a_marker(buf):
    jl.log_event("x", v="あ" * (jl.MAX_VALUE_CHARS + 25))
    v = lines(buf)[0]["v"]
    assert v.startswith("あ" * jl.MAX_VALUE_CHARS) and v.endswith("…(+25字)")


def test_nested_values_are_scrubbed_and_arbitrary_objects_are_not_repr_d(buf):
    class Secret:
        def __repr__(self) -> str:
            return "SECRET-REPR"

    jl.log_event("x", nested={"ip": "1.2.3.4", "ok": 1, "deep": {"a": {"b": {"c": {"d": 1}}}}}, obj=Secret(), items=[1, "a"] * 3)
    row = lines(buf)[0]
    assert row["nested"]["ip"] == jl.OMITTED and row["nested"]["ok"] == 1
    assert row["obj"] == "<Secret>" and "SECRET-REPR" not in buf.getvalue()
    assert row["nested"]["deep"]["a"]["b"]["c"] == jl.OMITTED  # 深すぎる入れ子は出さない


def test_reserved_keys_cannot_be_overwritten_by_fields(buf):
    jl.log_event("real_event", severity_x=1)
    jl.logging.getLogger(jl.LOGGER_NAME).info("real_event", extra={"fields": {"message": "forged", "severity": "CRITICAL"}})
    row = lines(buf)[1]
    assert row["message"] == "real_event" and row["severity"] == "INFO"
    assert row["field_message"] == "forged" and row["field_severity"] == "CRITICAL"


def test_setup_logging_is_idempotent(buf):
    jl.setup_logging("INFO", buf)
    jl.setup_logging("INFO", buf)
    jl.log_event("once")
    assert len(lines(buf)) == 1
    jl.log_event("debug_hidden", severity="debug")
    assert len(lines(buf)) == 1  # INFO に設定し直したので出ない


def test_log_exception_keeps_detail_private_and_reports_the_code(buf):
    exc = genai_errors.ClientError(404, {"error": {"message": "model not found", "status": "NOT_FOUND"}})
    jl.log_exception("model_call_failed", exc, run="r1")
    row = lines(buf)[0]
    assert row["severity"] == "ERROR" and row["error_code"] == "FATAL_CONFIG" and row["error_type"] == "ClientError"
    assert "model not found" in row["detail"] and "traceback" in row and row["run"] == "r1"


def test_log_exception_masks_ip_in_detail(buf):
    jl.log_exception("x", OSError("connect to 203.0.113.9 failed"))
    assert "203.0.113.9" not in buf.getvalue()


@pytest.mark.parametrize(
    "kw,expected",
    [
        (dict(), "INFO"),
        (dict(type=C.TraceType.POLICY_DECISION, decision=C.Decision.DENY, policy_id=C.PolicyId.LINK, reason_code="LINK_NOT_FOUND"), "WARNING"),
        (dict(type=C.TraceType.POLICY_DECISION, decision=C.Decision.DENY, policy_id=C.PolicyId.KILL, reason_code="KILLED"), "ERROR"),
        (dict(type=C.TraceType.POLICY_DECISION, decision=C.Decision.ALLOW, policy_id=C.PolicyId.SCOPE), "INFO"),
        (dict(type=C.TraceType.ABORT, reason_code="KILLED"), "ERROR"),
        (dict(type=C.TraceType.ABORT, reason_code="BUDGET"), "ERROR"),
        (dict(type=C.TraceType.ABORT, reason_code="CANCELLED"), "WARNING"),
    ],
)
def test_trace_severity(kw, expected):
    assert jl.trace_severity(make_event(**kw)) == expected


def test_trace_event_logging_round_trips_and_stays_one_line(buf):
    sig = C.InjectionSignal(pattern_id="p.ignore", doc_id="D1", visible=True, start=0, end=3, snippet="ignore previous")
    jl.log_trace_event(make_event(1, type=C.TraceType.INJECTION_SIGNAL, injection=sig, actor=C.Actor.VERIFIER))
    row = lines(buf)[0]
    assert row["event"] == "trace.injection_signal" and row["severity"] == "WARNING"
    assert row["run_id"].startswith("run_") and row["injection"]["pattern_id"] == "p.ignore"
