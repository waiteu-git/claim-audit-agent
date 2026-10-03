"""TraceLog: 1実行のトレースイベント（設計 §7）を採番して溜め、JSONL に書く。

イベントの型（TraceEvent）は contracts にあり、自由文のフィールドを持てない。ここは seq・t_ms・run_id の採番と、
400件の上限（MAX_EVENTS_PER_RUN）の管理だけを担当する。上限の手前で、判定・中断・予算の要約は必ず残す
（通常のイベントは MAX_EVENTS_PER_RUN - RESERVED_FOR_KEY_EVENTS 件で打切り、省略した数を omitted に数える）。
"""
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.contracts import MAX_EVENTS_PER_RUN, Actor, Phase, TraceEvent, TraceType

RESERVED_FOR_KEY_EVENTS = 60  # 判定（最大88件の要件）より少なくてよい。残りの要件の判定は省略数に数える
_KEY_TYPES = frozenset({TraceType.VERDICT, TraceType.ABORT, TraceType.BUDGET_SNAPSHOT})


def digest(obj: Any) -> str:
    """引数・結果の指紋（sha256 の先頭16字）。本文をトレースへ出さずに「同じ呼び出しか」だけを言うための値。"""
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8", "backslashreplace")).hexdigest()[:16]


class TraceLog:
    def __init__(
        self,
        run_id: str,
        clock_ms: Callable[[], int],
        *,
        max_events: int = MAX_EVENTS_PER_RUN,
        sink: Callable[[TraceEvent], None] | None = None,
    ) -> None:
        self.run_id = run_id
        self._clock_ms = clock_ms
        self._max = max_events
        self._sink = sink
        self._seq = 0
        self.events: list[TraceEvent] = []
        self.omitted = 0

    @property
    def next_seq(self) -> int:
        return self._seq

    def emit(self, phase: Phase, actor: Actor, type_: TraceType, **fields: Any) -> TraceEvent:
        """イベントを1つ作って返す。seq は上限で省略しても進める（証拠チップの event_seq が別のイベントを指さない）。"""
        ev = TraceEvent(
            run_id=self.run_id,
            seq=self._seq,
            t_ms=max(0, self._clock_ms()),
            phase=phase,
            actor=actor,
            type=type_,
            **fields,
        )
        self._seq += 1
        limit = self._max if type_ in _KEY_TYPES else max(0, self._max - RESERVED_FOR_KEY_EVENTS)
        if len(self.events) >= limit:
            self.omitted += 1
        else:
            self.events.append(ev)
            if self._sink is not None:
                self._sink(ev)
        return ev


def to_jsonl(events: "list[TraceEvent] | tuple[TraceEvent, ...]") -> str:
    """1行1イベントの JSON（None は省く）。"""
    return "".join(e.model_dump_json(exclude_none=True) + "\n" for e in events)


def write_jsonl(path: "str | Path", events: "list[TraceEvent] | tuple[TraceEvent, ...]") -> None:
    Path(path).write_text(to_jsonl(events), encoding="utf-8")
