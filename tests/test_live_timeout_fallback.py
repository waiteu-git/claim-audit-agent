"""ライブ実行が時間内に終わらなかった時（10/8: モデルの応答が遅く、①が 75 秒の壁時計で中断した）の挙動。

  * 1回の実行の時間上限は 100 秒（Cloud Run の timeout 120 秒の内側。切り替えの再生に数秒かかっても収まる）。
  * ライブが WALL_CLOCK で中断したら、判定のない中断の画面を出さず、保存済みの実行の再生へ自動で切り替える。
    画面に理由（LIVE_TIMEOUT）を出す。費用は実際に使った分で精算する。
  * 中断以外（完了・予算切れの部分結果）は、今までどおりその結果を出す。保存済みの実行を持たないプリセットは、中断の結果をそのまま出す。
"""
import asyncio
import dataclasses
from pathlib import Path

from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.config import RUN_CAPS, Settings, build_presets
from app.contracts import AbortReason, CheckClass, DegradedReason, Kind, Preset, RunStatus, Slot
from app.fixtures import gen
from app.fixtures.site import FixtureFetch, FixtureSite
from app.model.scripted import ScriptedPort
from tests.agent_support import FakeClock, raw, reader_reply
from tests.web_support import SELF, client, first, make_deps, run_preset, scripted_runner


def slow_runner():
    """Reader の応答が返った時点で壁時計の上限を超えていた実行（実測の「モデルが遅い時間帯」の再現）。"""

    async def run(preset: Preset, sink):
        clock = FakeClock()

        def slow_reader(_req):
            clock.advance(RUN_CAPS.wall_clock_s + 1)
            return reader_reply(raw(gen.Q_LENGTH, Kind.REQUIRED, CheckClass.LENGTH_LIMIT, slot=Slot.CHAR_LIMIT))

        fetch = FixtureFetch(FixtureSite.load(), preset.allowed_prefixes[0].host, preset.allowed_prefixes)
        return await run_audit(
            preset, fetch=fetch, reader_model=ScriptedPort([slow_reader]), planner_model=None, inspect_mode=InspectMode.ROUTER,
            settings=Settings(self_origin=SELF), trace_sink=sink, clock=clock,
        )  # fmt: skip

    return run


def test_the_run_time_cap_is_one_hundred_seconds_and_fits_inside_the_cloud_run_timeout():
    assert RUN_CAPS.wall_clock_s == 100
    deps = make_deps()
    assert deps.run_timeout_s < 120  # Cloud Run の timeout（deploy.sh の --timeout=120）の内側


def test_a_live_run_that_overruns_falls_back_to_the_saved_replay_with_the_reason():
    deps = make_deps(runner=slow_runner())
    status, ev = run_preset(client(deps), "sample_defect")
    assert status == 200
    modes = [d for name, d in ev if name == "mode"]
    assert modes[0]["mode"] == "LIVE"  # 始まりはライブ
    assert modes[-1] == {"mode": "REPLAY", "reason": "LIVE_TIMEOUT", "available": True, "switched": True}
    res = [d for name, d in ev if name == "result"]
    assert len(res) == 1  # 中断の結果は出さない。保存済みの実行の結果だけ
    assert res[0]["mode"] == "REPLAY" and res[0]["status"] == "DONE" and res[0]["verdicts"]
    names = [name for name, _ in ev]
    assert names[-1] == "done" and names.index("result") > max(i for i, n in enumerate(names) if n == "mode")


def test_the_replay_after_the_switch_is_the_bundled_record_of_that_preset():
    deps = make_deps(runner=slow_runner())
    live_status, live_ev = run_preset(client(deps), "sample_defect")
    bundled = deps.replays["sample_defect"].record
    got = first(live_ev, "result")
    assert got["preset_id"] == "sample_defect" and got["run_id"] == bundled.run_id


def test_the_cost_of_the_aborted_run_is_settled_at_the_actual_amount_not_the_worst_case():
    deps = make_deps(runner=slow_runner())
    run_preset(client(deps), "sample_defect")
    total = deps.quota.store.docs["dev/total"]
    assert total["reservations"] == {}  # 予約は残らない
    assert 0 < total["spent"]["anonymous"] < deps.quota.reservation  # 実際に使った分（中断した実行の見積もり）で精算


def test_a_run_that_finishes_in_time_is_not_replaced():
    deps = make_deps(runner=scripted_runner(InspectMode.ROUTER))
    status, ev = run_preset(client(deps), "sample_defect")
    modes = [d for name, d in ev if name == "mode"]
    assert len(modes) == 1 and modes[0]["mode"] == "LIVE"
    assert first(ev, "result")["mode"] == "LIVE" and first(ev, "result")["status"] == "DONE"


def test_without_a_bundled_record_the_aborted_result_is_shown_as_it_is():
    deps = make_deps(runner=slow_runner())
    deps.replays.pop("sample_defect")
    status, ev = run_preset(client(deps), "sample_defect")
    modes = [d for name, d in ev if name == "mode"]
    assert len(modes) == 1 and modes[0]["mode"] == "LIVE"
    res = first(ev, "result")
    assert res["mode"] == "LIVE" and res["status"] == "ABORTED" and res["aborted_reason"] == "WALL_CLOCK"


def test_the_outer_run_deadline_also_falls_back_and_settles_at_the_reserved_worst_case():
    """実行の外側の期限（run_timeout_s）で打ち切られた時（壁時計の判定に届く前に、応答の来ない呼び出しで固まった実行）。"""

    async def hang(preset: Preset, sink):
        await asyncio.sleep(3600)

    deps = make_deps(runner=hang, run_timeout_s=0.05)
    status, ev = run_preset(client(deps), "sample_defect")
    assert status == 200
    modes = [d for name, d in ev if name == "mode"]
    assert modes[0]["mode"] == "LIVE"
    assert modes[-1] == {"mode": "REPLAY", "reason": "LIVE_TIMEOUT", "available": True, "switched": True}
    assert not [d for name, d in ev if name == "error"]  # 利用者に出すのは理由つきの切り替えだけ
    assert first(ev, "result")["mode"] == "REPLAY" and [n for n, _ in ev][-1] == "done"
    total = deps.quota.store.docs["dev/total"]
    assert total["reservations"] == {} and total["spent"]["anonymous"] == deps.quota.reservation  # 費用が分からない＝最悪値


def test_a_timeout_error_raised_inside_the_run_is_not_a_live_timeout():
    """内側が自分で投げた TimeoutError（外側の期限ではない）は、これまでどおり一時的な失敗として出す。切り替えない。"""

    async def inner_timeout(preset: Preset, sink):
        raise TimeoutError("inner")

    deps = make_deps(runner=inner_timeout)
    status, ev = run_preset(client(deps), "sample_defect")
    assert status == 200
    assert [d for name, d in ev if name == "mode"] == [{"mode": "LIVE", "pool": "anonymous"}]
    assert first(ev, "error")["code"] == "RETRYABLE"
    assert first(ev, "result") is None


def test_the_outer_deadline_without_a_bundled_record_is_shown_as_the_error_it_was():
    async def hang(preset: Preset, sink):
        await asyncio.sleep(3600)

    deps = make_deps(runner=hang, run_timeout_s=0.05)
    deps.replays.pop("sample_defect")
    status, ev = run_preset(client(deps), "sample_defect")
    assert [d["mode"] for name, d in ev if name == "mode"] == ["LIVE"]
    assert first(ev, "error")["code"] == "RETRYABLE" and first(ev, "result") is None


def test_an_abort_for_another_reason_is_not_replaced():
    """壁時計以外の中断（キルスイッチなど）は、切り替えずにその結果を出す。"""
    inner = scripted_runner(InspectMode.ROUTER)

    async def killed(preset: Preset, sink):
        res = await inner(preset, sink)
        rec = res.record.model_copy(update={"status": RunStatus.ABORTED, "aborted_reason": AbortReason.KILL})
        return dataclasses.replace(res, record=rec)

    deps = make_deps(runner=killed)
    status, ev = run_preset(client(deps), "sample_defect")
    assert [d["mode"] for name, d in ev if name == "mode"] == ["LIVE"]
    res = first(ev, "result")
    assert res["mode"] == "LIVE" and res["status"] == "ABORTED" and res["aborted_reason"] == "KILL"


def test_every_preset_with_a_bundle_switches_to_its_own_record():
    """どのプリセットで中断しても、そのプリセット自身の同梱記録へ切り替わる（取得先に関わらず、中断の記録だけを作って確かめる）。"""
    base = scripted_runner(InspectMode.ROUTER)
    donor = build_presets(Settings(self_origin=SELF))["sample_defect"]

    async def overrun(preset: Preset, sink):
        res = await base(donor, sink)  # どのプリセットを選んでも、動く実行を1つ走らせて、壁時計の中断の記録にする
        rec = res.record.model_copy(update={"status": RunStatus.ABORTED, "aborted_reason": AbortReason.WALL_CLOCK})
        return dataclasses.replace(res, record=rec)

    for preset_id in ("lp_self", "sample_defect", "sample_injection"):
        deps = make_deps(runner=overrun)
        status, ev = run_preset(client(deps), preset_id)
        modes = [d for name, d in ev if name == "mode"]
        assert modes[-1]["reason"] == "LIVE_TIMEOUT", preset_id
        got = first(ev, "result")
        assert got["preset_id"] == preset_id and got["mode"] == "REPLAY" and got["run_id"] == deps.replays[preset_id].record.run_id


def test_a_failing_quota_store_does_not_stop_the_switch_from_reaching_the_user():
    """精算の失敗で、切り替えが落ちない（敵対レビュー: 結果を送る前に精算していたので、精算が例外を出すと何も届かなかった）。"""
    inner = slow_runner()
    deps = make_deps()

    async def run(preset: Preset, sink):
        res = await inner(preset, sink)
        deps.quota.store.fail = True  # 実行が終わった直後に、枠の保存先が落ちる
        return res

    deps.run_live = run
    status, ev = run_preset(client(deps), "sample_defect")
    assert status == 200
    modes = [d for name, d in ev if name == "mode"]
    assert modes[-1] == {"mode": "REPLAY", "reason": "LIVE_TIMEOUT", "available": True, "switched": True}
    assert first(ev, "result")["mode"] == "REPLAY" and [n for n, _ in ev][-1] == "done"
    assert not [d for name, d in ev if name == "error"]


def test_a_degraded_partial_result_is_shown_as_it_is_not_replaced():
    inner = scripted_runner(InspectMode.ROUTER)

    async def degraded(preset: Preset, sink):
        res = await inner(preset, sink)
        rec = res.record.model_copy(update={"status": RunStatus.DEGRADED, "degraded_reason": DegradedReason.BUDGET})
        return dataclasses.replace(res, record=rec)

    deps = make_deps(runner=degraded)
    status, ev = run_preset(client(deps), "sample_defect")
    assert [d["mode"] for name, d in ev if name == "mode"] == ["LIVE"]
    res = first(ev, "result")
    assert res["mode"] == "LIVE" and res["status"] == "DEGRADED"


def test_the_client_resets_and_explains_when_the_stream_switches_to_the_saved_run():
    js = Path("app/web/static/app.js").read_text(encoding="utf-8")
    block = js.split("function onMode")[1].split("function onError")[0]
    assert "m.switched" in block and "resetResult()" in block  # 途中までの表示を捨てる
    assert "ライブ実行が時間内に終わらなかったため、保存済みの実行を表示しています。" in js


def test_a_model_call_cut_at_the_wall_clock_ends_as_a_wall_clock_abort_charged_for_that_one_call_only():
    """WallBoundPort が壁時計＋余裕で呼び出しを打ち切った時（TimeoutError）も、結果は DEGRADED でなく WALL_CLOCK の中断になり、
    保存済みの実行へ切り替わる。精算は、打ち切った1回分の最悪値だけ（外側の期限で切られた時の予約の最悪値 ¥50 ではない）。"""

    async def cut(preset: Preset, sink):
        clock = FakeClock()

        def cut_reader(_req):
            clock.advance(RUN_CAPS.wall_clock_s + 2)  # 壁時計の締切＋余裕で打ち切られた時刻
            raise TimeoutError("cut by WallBoundPort")

        fetch = FixtureFetch(FixtureSite.load(), preset.allowed_prefixes[0].host, preset.allowed_prefixes)
        return await run_audit(
            preset, fetch=fetch, reader_model=ScriptedPort([cut_reader]), planner_model=None, inspect_mode=InspectMode.ROUTER,
            settings=Settings(self_origin=SELF), trace_sink=sink, clock=clock,
        )  # fmt: skip

    deps = make_deps(runner=cut)
    status, ev = run_preset(client(deps), "sample_defect")
    modes = [d for name, d in ev if name == "mode"]
    assert modes[-1] == {"mode": "REPLAY", "reason": "LIVE_TIMEOUT", "available": True, "switched": True}
    assert first(ev, "result")["mode"] == "REPLAY"
    spent = deps.quota.store.docs["dev/total"]["spent"]["anonymous"]
    assert 0 < spent < deps.quota.reservation // 2  # 打ち切った1回分（約 ¥6.5）。予約の最悪値（¥50）ではない
