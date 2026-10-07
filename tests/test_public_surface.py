"""公開面（S2）の自動テスト: 閉世界の入力・Origin・REPLAY への降格・SSE（ハートビート・切断）・CSP・漏洩の不在。

完了条件の確認もここ: プリセット②が REPLAY で表示でき、ライブ相当（ScriptedPort）で D1〜D4 のうち3件の不適合＋1件の矛盾、
プリセット③で警告帯（注入の件数）が出て、判定が全適合にならない。
"""
import asyncio
import logging

import pytest

from app.agent.planner import InspectMode
from app.config import PRESETS, QUOTA_POLICY, Settings
from app.errors import AppError, ErrorCode
from app.quota import Admission, InMemoryState, Pool, code_digest
from app.web.app import API_CSP, UI_CSP, live_events
from tests.web_support import (
    ORIGIN,
    SELF,
    client,
    first,
    live_settings,
    make_deps,
    parse_sse,
    run_preset,
    scripted_runner,
)

FAILS = "不適合"


def labels(result: dict) -> dict[str, str]:
    by_req = {r["req_id"]: (r["span"] or {}).get("original_span", "") for r in result["requirements"]}
    return {by_req[v["req_id"]]: v["label"] for v in result["verdicts"]}


# ---- 基本の経路 ----------------------------------------------------------------------------------
def test_health_returns_only_ok_true():
    r = client(make_deps()).get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("path", ["/probe", "/healthz", "/docs", "/openapi.json", "/api/run/x", "/fx/../app/main.py"])
def test_s1_probe_reserved_and_undeclared_paths_are_404(method, path):
    r = getattr(client(make_deps()), method)(path)
    assert r.status_code == 404
    assert "Traceback" not in r.text


def test_status_lists_the_three_presets_and_the_mode_without_any_url():
    r = client(make_deps(Settings(self_origin=SELF))).get("/api/status")
    data = r.json()
    assert data["mode"] == "REPLAY"
    assert [p["id"] for p in data["presets"]] == ["lp_self", "sample_defect", "sample_injection"]
    assert "https://" not in r.text and "example.invalid" not in r.text
    assert r.headers["content-security-policy"] == API_CSP


# ---- 閉世界の入力・Origin ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "body",
    [
        {"preset_id": "https://evil.example.invalid/"},
        {"preset_id": "lp_self", "url": "https://evil.example.invalid/"},
        {"url": "https://evil.example.invalid/"},
        {"preset_id": ["sample_defect"]},
        {"preset_id": "SAMPLE_DEFECT"},
        [],
        "sample_defect",
    ],
)
def test_anything_but_a_preset_id_is_400(body):
    r = client(make_deps()).post("/api/run", json=body, headers=ORIGIN)
    assert r.status_code == 400 and r.json() == {"ok": False, "code": "INVALID_INPUT"}


def test_non_json_and_oversized_bodies_are_refused():
    c = client(make_deps())
    assert c.post("/api/run", content=b"preset_id=sample_defect", headers={"origin": SELF, "content-type": "application/x-www-form-urlencoded"}).status_code == 400
    assert c.post("/api/run", content=b"{not json", headers=ORIGIN).status_code == 400
    big = b'{"preset_id":"sample_defect","pad":"' + b"x" * 5000 + b'"}'
    assert c.post("/api/run", content=big, headers=ORIGIN).status_code == 413


@pytest.mark.parametrize("origin", [None, "https://evil.example.invalid", "http://self.example.invalid", "https://self.example.invalid.evil.invalid", "null"])
def test_cross_origin_or_missing_origin_is_403(origin):
    headers = {"content-type": "application/json"}
    if origin is not None:
        headers["origin"] = origin
    deps = make_deps()
    r = client(deps).post("/api/run", json={"preset_id": "sample_defect"}, headers=headers)
    assert r.status_code == 403
    assert deps.quota.store.docs == {}  # 枠は消費されない


# ---- REPLAY への降格 -----------------------------------------------------------------------------
def test_live_disabled_replays_the_bundled_record_of_preset_2():
    status, ev = run_preset(client(make_deps(Settings(self_origin=SELF))), "sample_defect")
    assert status == 200
    assert first(ev, "mode") == {"mode": "REPLAY", "reason": "LIVE_DISABLED", "available": True}
    res = first(ev, "result")
    assert res["mode"] == "REPLAY" and res["status"] == "DONE"
    assert sum(1 for v in res["verdicts"] if v["label"] == FAILS) == 3 and len(res["contradictions"]) == 1
    assert len([e for e, _ in ev if e == "trace"]) == len(res["events"]) and ev[-1][0] == "done"


def test_kill_switch_degrades_to_replay_even_when_live_is_enabled():
    status, ev = run_preset(client(make_deps(live_settings(kill_switch=True))), "sample_defect")
    assert first(ev, "mode")["reason"] == "KILLED" and first(ev, "result")["mode"] == "REPLAY"


def test_a_daily_quota_of_zero_degrades_to_replay():
    policy = QUOTA_POLICY.model_copy(update={"anonymous": QUOTA_POLICY.anonymous.model_copy(update={"runs_per_day": 0})})
    deps = make_deps(policy=policy)
    status, ev = run_preset(client(deps), "sample_defect")
    assert first(ev, "mode")["reason"] == "QUOTA" and first(ev, "result")["mode"] == "REPLAY"


def test_a_failing_store_is_fail_closed_to_replay():
    store = InMemoryState()
    store.fail = True
    status, ev = run_preset(client(make_deps(store=store)), "sample_defect")
    assert first(ev, "mode")["reason"] == "STORE_UNAVAILABLE"


def test_a_preset_without_a_bundled_record_says_stopped_instead_of_inventing_one():
    # ①の記録は同梱した（10/7）。「記録の無いプリセット」は、①の記録だけを外した依存で再現する（記録が無ければ作り話をしない）
    deps = make_deps(Settings(self_origin=SELF))
    deps.replays.pop("lp_self")
    status, ev = run_preset(client(deps), "lp_self")
    assert first(ev, "mode")["available"] is False and first(ev, "result") is None
    assert first(ev, "error")["code"] == "KILLED"


def test_the_admit_gate_refuses_a_second_attempt_within_a_second():
    deps = make_deps(mono=lambda: 1000.0)
    c = client(deps)
    assert run_preset(c, "sample_defect")[0] == 200
    r = c.post("/api/run", json={"preset_id": "sample_defect"}, headers=ORIGIN)
    assert r.status_code == 429


# ---- ライブ相当（ScriptedPort）: 完了条件 -------------------------------------------------------
@pytest.mark.parametrize("mode", [InspectMode.ROUTER, InspectMode.PLANNER])
def test_live_preset_2_finds_three_failures_and_one_contradiction(mode):
    deps = make_deps(runner=scripted_runner(mode))
    status, ev = run_preset(client(deps), "sample_defect")
    assert first(ev, "mode")["mode"] == "LIVE"
    res = first(ev, "result")
    assert res["mode"] == "LIVE" and res["status"] == "DONE"
    lab = labels(res)
    from app.fixtures import gen

    assert lab[gen.Q_LENGTH] == FAILS and lab[gen.Q_AUTH] == FAILS and lab[gen.Q_LEAK] == FAILS  # D1・D2・D3
    assert [(c["slot"], c["tokens"]) for c in res["contradictions"]] == [("締切", ["10/15 23:59", "10/16 12:00"])]  # D4
    # 予約は実費で精算された（予約は残らず、使った額は予約額より小さい）
    total = deps.quota.store.docs["dev/total"]
    assert total["reservations"] == {} and 0 < total["spent"]["anonymous"] < deps.quota.reservation


def test_live_preset_3_shows_the_warning_counts_and_is_not_all_pass():
    status, ev = run_preset(client(make_deps()), "sample_injection")
    res = first(ev, "result")
    s = res["summary"]
    assert s["injection_visible"] >= 2 and s["injection_hidden"] >= 1
    assert {v["label"] for v in res["verdicts"]} != {"適合"} and s["verdict_counts"].get(FAILS, 0) == 3


def test_a_fatal_config_error_trips_kill_live_and_the_ui_mode_becomes_stopped():
    async def boom(preset, sink):
        raise AppError(ErrorCode.FATAL_CONFIG, "vertex 403 project=secret-project-id")

    deps = make_deps(runner=boom)
    c = client(deps)
    status, ev = run_preset(c, "sample_defect")
    err = first(ev, "error")
    assert err["code"] == "FATAL_CONFIG" and "secret-project-id" not in str(ev)
    assert deps.quota.store.docs["dev/control"]["kill_live"] is True
    deps.quota._kill_cache = None
    assert c.get("/api/status").json()["mode"] == "STOPPED"
    assert deps.quota.store.docs["dev/total"]["spent"]["anonymous"] == deps.quota.reservation  # 失敗は最悪値で精算


def test_an_unexpected_exception_shows_only_the_fixed_message():
    async def boom(preset, sink):
        raise RuntimeError("Traceback: /srv/app/secret.py line 3 token=abc")

    status, ev = run_preset(client(make_deps(runner=boom)), "sample_defect")
    err = first(ev, "error")
    assert err == {"code": "INTERNAL", "message": "内部エラーが発生しました。"}
    assert "secret" not in str(ev) and "Traceback" not in str(ev)


# ---- SSE: ハートビート・切断 ---------------------------------------------------------------------
def test_heartbeats_are_sent_while_the_run_is_quiet():
    async def slow():
        await asyncio.sleep(0.12)

    deps = make_deps(runner=scripted_runner(before=slow), heartbeat_s=0.02)
    status, ev = run_preset(client(deps), "sample_defect")
    assert ("heartbeat", None) in ev and first(ev, "result") is not None


async def test_a_disconnect_cancels_the_run_and_settles_the_reservation_at_the_worst_case():
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def hang(preset, sink):
        started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    deps = make_deps(runner=hang)
    adm = await deps.quota.admit(None)
    assert adm.live
    gen = live_events(deps, PRESETS["sample_defect"], adm)
    first_chunk = await gen.__anext__()
    assert first_chunk.startswith(b"event: mode")
    await asyncio.sleep(0)
    assert started.is_set()
    await gen.aclose()  # クライアント切断（StreamingResponse は生成器を閉じる）
    await asyncio.sleep(0)
    assert cancelled.is_set()
    total = deps.quota.store.docs["dev/total"]
    assert total["reservations"] == {} and total["spent"]["anonymous"] == deps.quota.reservation


# ---- 審査員コード --------------------------------------------------------------------------------
def test_a_judge_code_from_the_header_selects_the_judge_pool_and_only_a_hash_prefix_is_logged(caplog):
    code = "judge-demo-code-123"
    deps = make_deps(live_settings(judge_code_sha256=(code_digest(code),)))
    with caplog.at_level(logging.INFO):
        status, ev = run_preset(client(deps), "sample_defect", headers={"x-judge": code})
    assert first(ev, "mode") == {"mode": "LIVE", "pool": "judge"}
    from app.jsonlog import JsonFormatter

    lines = "\n".join(JsonFormatter().format(r) for r in caplog.records)  # 本番と同じ JSON 1行の形に直して確かめる
    assert code not in lines
    assert code_digest(code)[:8] in lines and code_digest(code)[:9] not in lines


def test_wrong_judge_codes_lock_after_five_failures_per_hour():
    good = "judge-demo-code-123"
    deps = make_deps(live_settings(judge_code_sha256=(code_digest(good),)))

    async def go():
        for _ in range(5):
            assert (await deps.quota.admit("wrong-code")).pool is not Pool.JUDGE
        return await deps.quota.admit(good)

    adm: Admission = asyncio.run(go())
    assert adm.pool is not Pool.JUDGE  # ロック中は正しいコードでも審査員枠に入らない


# ---- ヘッダ・CSP ---------------------------------------------------------------------------------
@pytest.mark.parametrize("path,ctype", [("/", "text/html"), ("/app.js", "text/javascript"), ("/app.css", "text/css")])
def test_ui_files_are_served_with_the_strict_csp(path, ctype):
    r = client(make_deps()).get(path)
    assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
    assert r.headers["content-security-policy"] == UI_CSP
    for part in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "connect-src 'self'"):
        assert part in UI_CSP
    assert "unsafe-inline" not in UI_CSP and "unsafe-eval" not in UI_CSP
    assert r.headers["x-content-type-options"] == "nosniff"


def test_fixtures_are_served_sandboxed_with_the_redirect_and_the_login_wall():
    c = client(make_deps())
    r = c.get("/fx/defect/spec/")
    assert r.status_code == 200 and r.headers["content-security-policy"].startswith("sandbox")
    r = c.get("/fx/defect/app/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/fx/defect/login/"
    assert 'type="password"' in c.get("/fx/defect/login/").text
    assert c.get("/fx/defect/app/REDIRECT").status_code == 404
    assert c.get("/fx/defect/spec", follow_redirects=False).status_code == 301
    for bad in ("/fx/defect/../../app/main.py", "/fx/defect/%2e%2e/x", "/fx//etc/passwd", "/fx/nothing/"):
        assert c.get(bad, follow_redirects=False).status_code == 404


def test_the_sse_response_is_not_cached_and_has_the_api_csp():
    r = client(make_deps(Settings(self_origin=SELF))).post("/api/run", json={"preset_id": "sample_defect"}, headers=ORIGIN)
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["cache-control"] == "no-store" and r.headers["content-security-policy"] == API_CSP
    assert parse_sse(r.text)[-1][0] == "done"
