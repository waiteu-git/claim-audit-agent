"""公開面（S2）のテスト用の組み立て。完全オフライン: 取得は FixtureFetch（フィクスチャをプロセス内で引く）、モデルは ScriptedPort、
枠の保存先は InMemoryState。SSE の本文を (event, data) の列に読む道具もここ。"""
import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.config import QUOTA_POLICY, Settings
from app.contracts import CheckClass, Kind, Preset, Slot, TraceEvent
from app.fixtures import gen
from app.fixtures.site import FixtureFetch, FixtureSite
from app.model.scripted import ScriptedPort, reply_calls
from app.quota import InMemoryState, QuotaService
from app.web.app import WebDeps, create_app
from app.web.replay import load_replays
from tests.agent_support import raw, reader_reply

SELF = "https://self.example.invalid"
ORIGIN = {"origin": SELF, "content-type": "application/json"}
NOON_UTC = datetime(2026, 10, 10, 3, 0, tzinfo=UTC)  # JST 12:00（匿名枠の 12 時の枠）


def live_settings(**kw) -> Settings:
    return Settings(self_origin=SELF, live_enabled=True, **kw)


def scripted_reader() -> ScriptedPort:
    """Reader の台本（ライブ相当）。要項（spec）と FAQ の2回分。引用は原文の1文をそのまま写す。"""
    spec = reader_reply(
        raw(gen.Q_DEADLINE_SPEC, Kind.REQUIRED, CheckClass.NONE, slot=Slot.DEADLINE),
        raw(gen.Q_LENGTH, Kind.REQUIRED, CheckClass.LENGTH_LIMIT, slot=Slot.CHAR_LIMIT),
        raw(gen.Q_AUTH, Kind.REQUIRED, CheckClass.AUTH_WALL, slot=Slot.URL),
        raw(gen.Q_LEAK, Kind.PROHIBITED, CheckClass.LEAK),
        raw(gen.Q_TEAM, Kind.REQUIRED, CheckClass.NONE, slot=Slot.TEAM_SIZE),
        raw(gen.Q_VIDEO, Kind.OPTIONAL, CheckClass.NONE),
    )
    faq = reader_reply(raw(gen.Q_DEADLINE_FAQ_CONFLICT, Kind.REQUIRED, CheckClass.NONE, slot=Slot.DEADLINE))
    return ScriptedPort([spec, faq], model_id="scripted-reader")


def scripted_planner() -> ScriptedPort:
    """Planner の台本: 提出URLの到達検査・認証壁・字数・漏洩は AUTORUN が済ませるので、残る要件は無く finish だけ。"""
    return ScriptedPort([reply_calls(("finish", {}))], model_id="scripted-planner")


def scripted_runner(mode: InspectMode = InspectMode.ROUTER, *, before: Callable | None = None):
    async def run(preset: Preset, sink: Callable[[TraceEvent], None]):
        if before is not None:
            await before()
        fetch = FixtureFetch(FixtureSite.load(), preset.allowed_prefixes[0].host, preset.allowed_prefixes)
        planner = scripted_planner() if mode is InspectMode.PLANNER else None
        return await run_audit(
            preset, fetch=fetch, reader_model=scripted_reader(), planner_model=planner, inspect_mode=mode,
            settings=Settings(self_origin=SELF), trace_sink=sink,
        )  # fmt: skip

    return run


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def make_deps(settings: Settings | None = None, *, runner=None, store=None, policy=QUOTA_POLICY, mono=None, **kw) -> WebDeps:
    settings = settings or live_settings()
    mono = mono or _advancing()
    quota = QuotaService(settings, store or InMemoryState(), policy=policy, now=lambda: NOON_UTC, monotonic=mono)
    return WebDeps(
        settings=settings, quota=quota, run_live=runner or scripted_runner(), fixtures=FixtureSite.load(), replays=load_replays(),
        replay_delay_s=0.0, **kw,
    )  # fmt: skip


def _advancing(step: float = 5.0):
    """呼ぶたびに進む時計（ADMIT ゲートの1試行/秒に当たらないように）。"""
    t = [1000.0]

    def clock() -> float:
        t[0] += step
        return t[0]

    return clock


def client(deps: WebDeps) -> TestClient:
    return TestClient(create_app(deps.settings, deps), base_url=SELF)


def parse_sse(text: str) -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        if block.startswith(":"):
            out.append(("heartbeat", None))
            continue
        event, data = "message", []
        for line in block.split("\n"):
            if line.startswith("event: "):
                event = line[7:]
            elif line.startswith("data: "):
                data.append(line[6:])
        out.append((event, json.loads("\n".join(data)) if data else None))
    return out


def run_preset(c: TestClient, preset_id: str, headers: dict | None = None) -> tuple[int, list[tuple[str, object]]]:
    r = c.post("/api/run", json={"preset_id": preset_id}, headers={**ORIGIN, **(headers or {})})
    return r.status_code, (parse_sse(r.text) if r.headers.get("content-type", "").startswith("text/event-stream") else [])


def first(events, name):
    return next((d for e, d in events if e == name), None)


def run_async(coro):
    return asyncio.run(coro)
