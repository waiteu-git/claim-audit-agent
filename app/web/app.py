"""公開面（S2）の Web サービス。審査員が触れる入口（設計 §2・§6・§8）。

  GET  /health        {"ok": true} だけ（Cloud Run は /healthz を予約しているので使わない）
  GET  /  /app.js  /app.css   静的 UI（フレームワーク・外部 CDN・インラインの script/style 無し。CSP で self だけ）
  GET  /fx/{path}     架空フィクスチャの配信（app/fixtures/site.py の FixtureSite。sandbox の CSP）
  GET  /api/status    モード（LIVE／REPLAY／STOPPED）とプリセットの一覧（入力欄は無い。選べるのはプリセットだけ）
  POST /api/run       {"preset_id": "..."} だけを受ける（閉世界: 任意の URL は受けない）。応答は text/event-stream
  /probe は持たない（S1 の疎通確認専用。公開面では 404）。

POST /api/run の守り（上から順に）:
  1. Origin が自 origin（SELF_ORIGIN）でなければ 403（他サイトからの起動＝費用の踏み台にさせない）
  2. 本文は JSON・4KB 以下・{"preset_id"} だけ。プリセット ID 以外は 400
  3. ADMIT 前段のゲート（1試行/秒）→ 429。枠・キルスイッチ・上限の判断は quota.QuotaService（LIVE か REPLAY か）
  4. LIVE: 実行をタスクで走らせ、トレースを SSE で流す。10秒ごとにハートビート。切断されたら実行を取り消し、予約は最悪値で精算
     （応答が戻らない呼び出しの費用は分からない＝安全側）。完了したら実費（トレースの見積もり）で精算。
     ライブが時間内に終わらなかった時（壁時計の上限での中断、または実行の外側の期限）は、判定のない中断の画面を出さず、
     mode（REPLAY・理由 LIVE_TIMEOUT・switched）を送って保存済みの実行へ切り替える（そのプリセットの同梱記録がある時だけ）
  5. REPLAY: 同梱の実行記録（app/web/replay/）を流す。Vertex・Firestore に依存しない
SSE のイベント: mode（LIVE/REPLAY と理由）・trace（TraceEvent）・result（RunRecord）・error（ErrorCode と固定文だけ）・done。
例外の中身（str(e)・スタックトレース）は応答に出さない（非公開ログだけ）。
"""
import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.agent.planner import InspectMode
from app.agent.report import report_json
from app.agent.run import RunResult, run_audit
from app.config import (
    GUARD_LIMITS,
    MAX_REQUEST_BODY_BYTES,
    PRESET_IDS,
    RUN_CAPS,
    FetchBackend,
    Settings,
    StateBackend,
    build_presets,
    get_settings,
)
from app.contracts import AbortReason, FetchPort, Preset, RunRecord, RunStatus, TraceEvent
from app.egress_guard import EgressGuard
from app.errors import ErrorCode, PublicError, classify
from app.fixtures.site import FixtureSite
from app.jsonlog import log_event, log_exception
from app.model.port import ModelPort
from app.model.retry import RetryingPort
from app.model.wallbound import WallBoundPort
from app.quota import Admission, AdmitRejected, InMemoryState, QuotaService, ReplayReason, StatePort
from app.web.examples import build_examples
from app.web.replay import ReplayBundle, load_replays

STATIC_DIR = Path(__file__).resolve().parent / "static"
UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
COMMON_HEADERS = {"x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store"}
JUDGE_HEADER = "x-judge"

LiveRunner = Callable[[Preset, Callable[[TraceEvent], None]], Awaitable[RunResult]]

CLOUD_RUN_TIMEOUT_S = 120.0  # deploy.sh の --timeout（SSE の応答も、受付から終わりまでこの中）
SWITCH_RESERVE_S = 12.0  # 外側の期限の後に要る分: 取り消しの後始末（最大1秒）・切り替えの再生（約1.5秒）・精算・通信の余裕


@dataclass
class WebDeps:
    settings: Settings
    quota: QuotaService
    run_live: LiveRunner
    fixtures: FixtureSite
    replays: dict[str, ReplayBundle]
    replay_delay_s: float = 0.03
    heartbeat_s: float = GUARD_LIMITS.sse_heartbeat_s
    run_timeout_s: float = RUN_CAPS.wall_clock_s + 10.0  # Cloud Run の timeout（120 秒）の内側。切り替えの再生の分（数秒）を残す


def sse(event: str, data: str) -> bytes:
    """SSE の1イベント。data は1行の JSON（改行を含まない）。"""
    return f"event: {event}\ndata: {data}\n\n".encode("utf-8")


HEARTBEAT = b": hb\n\n"


def _json(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


# ---- 既定の組み立て（本番）-----------------------------------------------------------------------
def _build_fetch(settings: Settings, preset: Preset) -> FetchPort:
    if settings.fetch_backend is FetchBackend.REMOTE:
        from app.net.fetcher_client import RemoteFetch, metadata_token_provider

        if settings.fetcher_url is None:
            raise RuntimeError("FETCH_MODE=remote には FETCHER_URL が要ります")
        return RemoteFetch(settings.fetcher_url, metadata_token_provider(settings.fetcher_url))
    from app.net.safefetch import SafeFetch

    return SafeFetch(preset.allowed_prefixes)


def bound_model(port: ModelPort, *, deadline_monotonic: float) -> ModelPort:
    """再試行（壁時計の締切で止める）を、壁時計の内側に収める。応答の遅い時間帯に、呼び出し中のまま外側の期限へ当たらないように。"""
    retrying = RetryingPort(port, retries=RUN_CAPS.model_retries, backoff_s=RUN_CAPS.retry_backoff_s, deadline_monotonic=deadline_monotonic)
    return WallBoundPort(retrying, deadline_monotonic=deadline_monotonic)


def default_live_runner(settings: Settings) -> LiveRunner:  # pragma: no cover - Vertex を呼ぶ（テストは注入する）
    async def run(preset: Preset, sink: Callable[[TraceEvent], None]) -> RunResult:
        from app.model.gemini import GeminiPort

        deadline = time.monotonic() + RUN_CAPS.wall_clock_s  # BudgetMeter の起点とのずれは、WallBoundPort の余裕（2秒）に収まる

        def model(model_id: str) -> ModelPort:
            return bound_model(GeminiPort.from_settings(settings, model_id=model_id), deadline_monotonic=deadline)

        return await run_audit(
            preset,
            fetch=_build_fetch(settings, preset),
            reader_model=model(settings.gemini_model_reader),
            planner_model=model(settings.gemini_model_planner),
            inspect_mode=InspectMode.PLANNER,
            settings=settings,
            trace_sink=sink,
        )

    return run


def _default_store(settings: Settings) -> StatePort:  # pragma: no cover - 本番は Firestore
    if settings.state_backend is StateBackend.FIRESTORE:
        from app.state_firestore import FirestoreState

        return FirestoreState.from_project(settings.google_cloud_project)
    return InMemoryState()


def default_deps(settings: Settings) -> WebDeps:  # pragma: no cover - 本番の配線
    return WebDeps(
        settings=settings,
        quota=QuotaService(settings, _default_store(settings)),
        run_live=default_live_runner(settings),
        fixtures=FixtureSite.load(),
        replays=load_replays(),
    )


# ---- SSE の流れ ----------------------------------------------------------------------------------
SWITCH_REPLAY_DELAY_S = 0.01  # 実行の途中で保存済みの実行へ切り替えた時の流す間隔（利用者はすでに待った。timeout の残りも小さい）


def _live_overran(rec: RunRecord) -> bool:
    """ライブが壁時計の上限で中断した記録か（判定のない中断。保存済みの実行へ切り替える対象）。"""
    return rec.status is RunStatus.ABORTED and rec.aborted_reason is AbortReason.WALL_CLOCK


async def _replay_body(bundle: ReplayBundle, delay_s: float) -> AsyncIterator[bytes]:
    """同梱の実行記録の trace と result（mode と done は呼び出し側が送る）。"""
    for ev in bundle.event_jsons:
        if delay_s:
            await asyncio.sleep(delay_s)
        yield sse("trace", ev)
    yield sse("result", bundle.record_json)


def run_budget_s(deps: WebDeps, t_request: float, now: float) -> float:
    """ライブの実行に与える外側の期限（秒）。受付から Cloud Run の timeout までの間に、切り替えの分（SWITCH_RESERVE_S）を残す。"""
    return min(deps.run_timeout_s, max(1.0, CLOUD_RUN_TIMEOUT_S - SWITCH_RESERVE_S - (now - t_request)))


async def live_events(deps: WebDeps, preset: Preset, adm: Admission, t_request: float | None = None) -> AsyncIterator[bytes]:
    """LIVE の SSE。切断（aclose・取り消し）されたら実行を取り消し、予約を最悪値で精算する。

    ライブが時間内に終わらなかった時（壁時計の上限での中断、または実行の外側の期限）は、そのプリセットの同梱記録があれば
    mode（REPLAY・LIVE_TIMEOUT・switched）を送って保存済みの実行へ切り替える。中断の結果（判定のない画面）は送らない。
    """
    queue: asyncio.Queue[TraceEvent] = asyncio.Queue()
    outer_expired = False  # 実行の外側の期限で打ち切った
    budget_s = run_budget_s(deps, t_request if t_request is not None else time.monotonic(), time.monotonic())

    async def run() -> RunResult:
        nonlocal outer_expired
        limit = asyncio.timeout(budget_s)
        try:
            async with limit:
                return await deps.run_live(preset, queue.put_nowait)
        except TimeoutError:
            outer_expired = limit.expired()  # 内側が自分で投げた TimeoutError とは区別する
            raise

    bundle = deps.replays.get(preset.preset_id)
    task = asyncio.ensure_future(run())
    getter: asyncio.Future | None = None
    settled = False
    try:
        yield sse("mode", _json({"mode": "LIVE", "pool": adm.pool.value if adm.pool else None}))
        while True:
            if getter is None:
                getter = asyncio.ensure_future(queue.get())
            done, _ = await asyncio.wait({getter, task}, timeout=deps.heartbeat_s, return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                ev = getter.result()
                getter = None
                yield sse("trace", ev.model_dump_json(exclude_none=True))
                continue
            if task in done:
                while not queue.empty():
                    yield sse("trace", queue.get_nowait().model_dump_json(exclude_none=True))
                break
            yield HEARTBEAT
        switch = False  # 保存済みの実行へ切り替える（同梱記録がある時だけ）
        try:
            res = task.result()
        except Exception as e:  # noqa: BLE001  公開してよいのは ErrorCode と固定文だけ
            code = classify(e)
            log_exception("web.run_failed", e)
            if code is ErrorCode.FATAL_CONFIG:
                await deps.quota.trip_kill()
            if outer_expired and bundle is not None:
                switch = True  # 費用は分からない＝finally が予約の最悪値で精算する
            else:
                yield sse("error", PublicError.from_code(code).model_dump_json())
        else:
            if bundle is not None and _live_overran(res.record):
                switch = True
                try:
                    await deps.quota.settle(adm, res.record.summary.est_cost_micro_jpy)  # 使った分（実費）で精算する
                    settled = True
                except Exception as e:  # noqa: BLE001  精算の失敗で、利用者への切り替えを落とさない（finally が最悪値で精算し直す）
                    log_exception("web.settle_failed", e)
            else:
                yield sse("result", report_json(res.record))
                await deps.quota.settle(adm, res.record.summary.est_cost_micro_jpy)
                settled = True
        if switch and bundle is not None:
            log_event("web.live_timeout_fallback", severity="WARNING", preset_id=preset.preset_id, outer=outer_expired)
            yield sse("mode", _json({"mode": "REPLAY", "reason": ReplayReason.LIVE_TIMEOUT.value, "available": True, "switched": True}))
            async for chunk in _replay_body(bundle, min(deps.replay_delay_s, SWITCH_REPLAY_DELAY_S)):
                yield chunk
        yield sse("done", "{}")
    finally:
        if getter is not None:
            getter.cancel()
        if not task.done():
            task.cancel()
            log_event("web.run_cancelled", severity="WARNING")
        if not settled:
            with anyio.CancelScope(shield=True):
                try:
                    await deps.quota.settle(adm, adm.reserved_micro_jpy)  # 費用が分からない＝予約額（最悪値）で精算
                except Exception as e:  # noqa: BLE001
                    log_exception("web.settle_failed", e)


async def replay_events(deps: WebDeps, preset_id: str, reason: ReplayReason | None) -> AsyncIterator[bytes]:
    bundle = deps.replays.get(preset_id)
    yield sse("mode", _json({"mode": "REPLAY", "reason": reason.value if reason else None, "available": bundle is not None}))
    if bundle is None:
        code = ErrorCode.KILLED if reason in (ReplayReason.KILLED, ReplayReason.LIVE_DISABLED) else ErrorCode.QUOTA
        yield sse("error", PublicError.from_code(code).model_dump_json())
        yield sse("done", "{}")
        return
    async for chunk in _replay_body(bundle, deps.replay_delay_s):
        yield chunk
    yield sse("done", "{}")


# ---- アプリ ------------------------------------------------------------------------------------
def create_app(settings: Settings | None = None, deps: WebDeps | None = None) -> FastAPI:
    settings = settings or get_settings()
    deps = deps or default_deps(settings)
    presets = build_presets(settings)
    examples = build_examples(presets)  # 正解表と同梱の記録がずれていれば、ここで起動を止める
    app = FastAPI(title="claim-audit-agent", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.deps = deps
    static = {path: ((STATIC_DIR / name).read_bytes(), ctype) for path, (name, ctype) in STATIC_FILES.items()}

    def self_origin(request: Request) -> str:
        if settings.self_origin:
            return settings.self_origin.rstrip("/")
        return f"{request.url.scheme}://{request.headers.get('host', '')}"  # 開発: 同じホストだけ

    def deny(status: int, code: ErrorCode) -> JSONResponse:
        return JSONResponse({"ok": False, "code": code.value}, status_code=status, headers={"content-security-policy": API_CSP})

    @app.exception_handler(Exception)
    async def on_error(request: Request, exc: Exception) -> JSONResponse:
        log_exception("web.unhandled", exc)
        return deny(500, ErrorCode.INTERNAL)

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True}

    def static_route(path: str) -> None:
        body, ctype = static[path]

        async def serve() -> Response:
            return Response(body, media_type=ctype, headers={"content-security-policy": UI_CSP})

        app.add_api_route(path, serve, methods=["GET"], include_in_schema=False)

    for path in static:
        static_route(path)

    @app.get("/fx/{path:path}")
    async def fixtures(path: str) -> Response:
        r = deps.fixtures.resolve("/fx/" + path)
        return Response(r.body, status_code=r.status, headers=dict(r.headers))

    @app.get("/api/status")
    async def status() -> JSONResponse:
        return JSONResponse(
            {
                "mode": await deps.quota.mode(),
                "caps": {
                    "model_calls": RUN_CAPS.model_calls_total, "tokens_in": RUN_CAPS.tokens_in, "tokens_out": RUN_CAPS.tokens_out,
                    "tool_calls": RUN_CAPS.tool_calls, "fetches": RUN_CAPS.fetches_total, "wall_ms": int(RUN_CAPS.wall_clock_s * 1000),
                },  # fmt: skip
                "presets": [
                    {"id": pid, "label": presets[pid].label_ja, "kind": presets[pid].kind.value, "replay": pid in deps.replays, **examples[pid]}
                    for pid in PRESET_IDS
                ],
            },
            headers={"content-security-policy": API_CSP},
        )

    @app.post("/api/run")
    async def api_run(request: Request) -> Response:
        if request.headers.get("origin", "").rstrip("/") != self_origin(request):
            return deny(403, ErrorCode.INVALID_INPUT)
        if "application/json" not in request.headers.get("content-type", ""):
            return deny(400, ErrorCode.INVALID_INPUT)
        body = await request.body()
        if len(body) > MAX_REQUEST_BODY_BYTES:
            return deny(413, ErrorCode.INVALID_INPUT)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return deny(400, ErrorCode.INVALID_INPUT)
        if not isinstance(data, dict) or set(data) != {"preset_id"} or data["preset_id"] not in PRESET_IDS:
            return deny(400, ErrorCode.INVALID_INPUT)
        preset_id: str = data["preset_id"]
        t_request = time.monotonic()  # Cloud Run の timeout は受付から数える（外側の期限の計算の起点）
        try:
            adm = await deps.quota.admit(request.headers.get(JUDGE_HEADER))
        except AdmitRejected:
            return deny(429, ErrorCode.QUOTA)
        log_event("web.run_admitted", preset_id=preset_id, live=adm.live, reason=adm.replay_reason)
        stream = live_events(deps, presets[preset_id], adm, t_request) if adm.live else replay_events(deps, preset_id, adm.replay_reason)
        return StreamingResponse(
            stream,
            media_type="text/event-stream",
            headers={"content-security-policy": API_CSP, "cache-control": "no-store", "x-accel-buffering": "no"},
        )

    app.add_middleware(SecurityHeaders)
    app.add_middleware(EgressGuard)  # 最も外側（全パス共通の上限）
    return app


class SecurityHeaders:
    """全応答に共通のヘッダを足す素の ASGI ミドルウェア（SSE を包んでも、切断の伝わり方を変えない）。"""

    def __init__(self, app) -> None:  # noqa: ANN001
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def wrapped(message) -> None:  # noqa: ANN001
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for k, v in COMMON_HEADERS.items():
                    if k.encode() not in present:
                        headers.append((k.encode(), v.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, wrapped)
