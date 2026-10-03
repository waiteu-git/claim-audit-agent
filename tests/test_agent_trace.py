"""trace.py: 採番・上限・JSONL。"""
import json

from app.agent.trace import RESERVED_FOR_KEY_EVENTS, TraceLog, digest, to_jsonl, write_jsonl
from app.contracts import MAX_EVENTS_PER_RUN, Actor, Decision, Phase, PolicyId, TraceType, VerdictLabel

RUN = "run_AAAAAAAAAAAAAAAAAAAAAA"


def make(**kw):
    t = [0]

    def clock():
        t[0] += 7
        return t[0]

    return TraceLog(RUN, clock, **kw)


def test_seq_and_time_increase_and_run_id_is_stamped():
    log = make()
    a = log.emit(Phase.ACQUIRE, Actor.GOVERNOR, TraceType.PHASE_ENTER, name="ACQUIRE")
    b = log.emit(Phase.READ, Actor.GOVERNOR, TraceType.PHASE_ENTER, name="READ")
    assert (a.seq, b.seq) == (0, 1) and b.t_ms > a.t_ms and a.run_id == RUN
    assert log.events == [a, b] and log.omitted == 0


def test_digest_is_deterministic_and_order_independent_but_sensitive_to_content():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert digest({"a": 1}) != digest({"a": 2})
    assert len(digest("x")) == 16


def test_ordinary_events_stop_before_the_cap_but_verdicts_and_aborts_are_kept():
    log = make(max_events=100)
    for _ in range(100):
        log.emit(Phase.INSPECT, Actor.TOOL, TraceType.TOOL_RESULT, name="run_check")
    ordinary = 100 - RESERVED_FOR_KEY_EVENTS
    assert len(log.events) == ordinary and log.omitted == RESERVED_FOR_KEY_EVENTS
    v = log.emit(Phase.ADJUDICATE, Actor.ADJUDICATOR, TraceType.VERDICT, req_id="R1", verdict=VerdictLabel.FAIL)
    ab = log.emit(Phase.INSPECT, Actor.GOVERNOR, TraceType.ABORT, reason_code="KILL")
    assert v in log.events and ab in log.events
    assert v.seq == 100  # 省略したイベントにも seq を振る（証拠チップの event_seq が別のイベントを指さない）


def test_total_never_exceeds_the_run_record_limit():
    log = make()
    for _ in range(MAX_EVENTS_PER_RUN + 50):
        log.emit(Phase.ADJUDICATE, Actor.ADJUDICATOR, TraceType.VERDICT, req_id="R1", verdict=VerdictLabel.FAIL)
    assert len(log.events) == MAX_EVENTS_PER_RUN and log.omitted == 50


def test_jsonl_is_one_event_per_line_without_nulls(tmp_path):
    log = make()
    log.emit(Phase.INSPECT, Actor.GOVERNOR, TraceType.POLICY_DECISION, policy_id=PolicyId.DUP, decision=Decision.DENY, reason_code="DUPLICATE_CALL")
    log.emit(Phase.INSPECT, Actor.TOOL, TraceType.TOOL_RESULT, name="run_check")
    text = to_jsonl(log.events)
    lines = text.splitlines()
    assert len(lines) == 2 and text.endswith("\n")
    first = json.loads(lines[0])
    assert first["policy_id"] == "P-DUP-01" and "req_id" not in first
    p = tmp_path / "t.jsonl"
    write_jsonl(p, log.events)
    assert p.read_text(encoding="utf-8") == text


def test_sink_receives_only_kept_events():
    got = []
    log = make(max_events=RESERVED_FOR_KEY_EVENTS + 1, sink=got.append)
    for _ in range(3):
        log.emit(Phase.INSPECT, Actor.TOOL, TraceType.TOOL_RESULT, name="x")
    assert len(got) == 1 and got == log.events
