"""測定の道具（python -m app.fixtures.eval）: オフラインの表・--live の上限・出力。実モデルは呼ばない（--live は偽のポートで試す）。"""
import asyncio
import json

import pytest

from app.agent.planner import InspectMode
from app.config import Settings
from app.contracts import ModelPurpose, ModelRequest
from app.errors import AppError, ErrorCode
from app.fixtures import eval as ev
from app.fixtures import gen, measure
from app.fixtures.eval import OracleReader, RulePlanner


def rows_by(table):
    return {(r["variant"], r["mode"]): r for r in table["rows"]}


@pytest.fixture(scope="module")
def offline():
    return asyncio.run(measure.measure_offline())


def test_the_offline_table_covers_every_variant_in_both_modes_in_the_agreed_order(offline):
    assert [(r["variant"], r["mode"]) for r in offline["rows"]] == [
        (v.name, m) for v in (*gen.GUIDE_VARIANTS, *gen.VARIANTS) for m in ("planner", "router")
    ]
    assert offline["live"] is False and all(r["tokens_source"] == "estimated" for r in offline["rows"])
    assert all(r["status"] == "DONE" and not r["skipped"] for r in offline["rows"])


def test_the_offline_table_is_deterministic(offline):
    assert asyncio.run(measure.measure_offline()) == offline


def test_a_false_absent_appears_only_where_the_router_does_not_follow_the_guide_page(offline):
    r = rows_by(offline)
    assert (r[("g1found", "planner")]["false_absent"], r[("g1found", "router")]["false_absent"]) == (0, 1)
    assert sum(x["false_absent"] for x in offline["rows"]) == 1
    assert offline["totals"]["router"]["false_absent"] == 1 and offline["totals"]["planner"]["false_absent"] == 0
    assert (r[("g1found", "planner")]["replans"], r[("g1found", "router")]["replans"]) == (1, 0)


def test_the_table_counts_what_was_done_without_flattering_the_planner(offline):
    r = rows_by(offline)
    # 辿る分、Planner は手数もモデル呼び出しも費用も router より多い（良く見せる処理は入れない）
    assert r[("g1found", "planner")]["tool_calls"] > r[("g1found", "router")]["tool_calls"]
    assert r[("g1found", "planner")]["model_calls"] > r[("g1found", "router")]["model_calls"]
    assert r[("g1found", "planner")]["est_cost_jpy"] > r[("g1found", "router")]["est_cost_jpy"]
    # 欠陥の検出は同じ（検出 x/y の分母・分子とも）
    assert all(r[(v.name, "planner")]["detected"] == r[(v.name, "router")]["detected"] for v in gen.VARIANTS)
    # 確認不能の件数は両方で同じ（案内ページを辿っても、締切・人数などの検査できない要件は確認不能のまま）
    assert all(r[(v.name, "planner")]["unverifiable"] == r[(v.name, "router")]["unverifiable"] for v in (*gen.VARIANTS, *gen.GUIDE_VARIANTS))


def test_the_offline_path_never_builds_a_gemini_port(monkeypatch):
    import app.model.gemini as g

    def boom(*a, **k):
        raise AssertionError("オフラインで GeminiPort を作った")

    monkeypatch.setattr(g.GeminiPort, "from_settings", classmethod(boom))
    table = asyncio.run(measure.measure_offline(gen.GUIDE_VARIANTS[:1]))
    assert [r["mode"] for r in table["rows"]] == ["planner", "router"]


# ---- --live の上限（偽のポートで試す。実モデルは呼ばない）---------------------------------------------------
class FakeLive:
    """GeminiPort の代わり。Reader は OracleReader、Planner は RulePlanner に委ね、呼ばれた回数を数える。"""

    calls = 0
    fail_first = False

    def __init__(self, model_id: str) -> None:
        self._id = model_id
        self._reader, self._planner = OracleReader(), RulePlanner()

    @property
    def model_id(self) -> str:
        return self._id

    async def generate(self, request: ModelRequest):
        FakeLive.calls += 1
        if FakeLive.fail_first and FakeLive.calls == 1:
            raise AppError(ErrorCode.RETRYABLE, "x")
        inner = self._reader if request.purpose is ModelPurpose.READER else self._planner
        return await inner.generate(request)


@pytest.fixture()
def fake_live(monkeypatch):
    import app.model.gemini as g

    FakeLive.calls, FakeLive.fail_first = 0, False
    monkeypatch.setattr(g.GeminiPort, "from_settings", classmethod(lambda cls, settings, model_id, client=None: FakeLive(model_id)))

    async def no_sleep(_s):  # 再試行の待ちを実際には待たない
        return None

    monkeypatch.setattr("asyncio.sleep", no_sleep)
    return FakeLive


def live_settings():
    return Settings(google_cloud_project="demo-project-id")


def test_live_stops_at_the_call_cap_and_marks_the_rest_as_skipped(fake_live):
    table = asyncio.run(measure.measure_live(live_settings(), max_calls=10))
    assert fake_live.calls <= 10 and table["calls_used"] == fake_live.calls <= table["calls_limit"] == 10
    done = [r for r in table["rows"] if not r.get("skipped")]
    skipped = [r for r in table["rows"] if r.get("skipped")]
    assert done and skipped and len(done) + len(skipped) == 16
    assert all(r["status"] == "skipped" and "上限" in r["reason"] for r in skipped)
    assert all(r["tokens_source"] == "measured" for r in done)
    assert table["rows"][0]["variant"] == "g1found"  # 差が出る変種から測る


def test_the_default_cap_is_forty_and_never_exceeded_even_with_retries(fake_live):
    fake_live.fail_first = True  # 最初の1回が一時的な失敗 → 再試行も1回と数える
    table = asyncio.run(measure.measure_live(live_settings()))
    assert table["calls_limit"] == measure.MAX_LIVE_CALLS_DEFAULT == 40
    assert fake_live.calls <= 40 and table["calls_used"] == fake_live.calls
    assert table["calls_used"] > 0


def test_a_run_that_hits_the_cap_midway_is_reported_as_it_is(fake_live):
    table = asyncio.run(measure.measure_live(live_settings(), max_calls=3, only=["g1found"]))
    first = table["rows"][0]
    assert first["mode"] == "planner" and first["status"] in {"DEGRADED", "DONE"} and fake_live.calls == 3
    assert table["rows"][1]["skipped"] is True


def test_the_cap_has_a_hard_upper_bound_and_a_lower_bound():
    for bad in (0, -1, measure.MAX_LIVE_CALLS_HARD + 1):
        with pytest.raises(ValueError):
            measure.CallBudget(bad)
    assert measure.CallBudget(measure.MAX_LIVE_CALLS_HARD).left == measure.MAX_LIVE_CALLS_HARD


def test_a_capped_port_does_not_call_the_inner_port_after_the_cap():
    calls = []

    class Inner:
        model_id = "inner"

        async def generate(self, request):
            calls.append(1)
            return None

    port = measure.CappedPort(Inner(), measure.CallBudget(2))
    req = ModelRequest(purpose=ModelPurpose.READER, system="s", contents="c", max_output_tokens=10, timeout_s=1)

    async def go():
        await port.generate(req)
        await port.generate(req)
        with pytest.raises(AppError) as e:
            await port.generate(req)
        return e.value.code

    assert asyncio.run(go()) is ErrorCode.QUOTA and len(calls) == 2


def test_live_without_a_project_calls_nothing(monkeypatch, capsys):
    import app.model.gemini as g

    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setattr(g.GeminiPort, "from_settings", classmethod(lambda *a, **k: (_ for _ in ()).throw(AssertionError("呼んだ"))))
    assert ev.main(["--live"]) == 2
    assert "GOOGLE_CLOUD_PROJECT" in capsys.readouterr().err


# ---- 出力 ----------------------------------------------------------------------------------------------
def test_main_prints_a_markdown_table_and_json_by_default_and_each_alone(capsys):
    assert ev.main(["--only", "g1found"]) == 0
    out = capsys.readouterr().out
    md, js = out.split("\n\n{", 1)
    assert md.startswith("| 変種 | 検査 | モデル |") and "| g1found | router |" in md and "誤った absent" in md
    data = json.loads("{" + js)
    assert data["live"] is False and [r["mode"] for r in data["rows"]] == ["planner", "router"]
    assert ev.main(["--md", "--only", "g1found"]) == 0 and capsys.readouterr().out.lstrip().startswith("| 変種")
    assert ev.main(["--json", "--only", "g1found"]) == 0 and json.loads(capsys.readouterr().out)["totals"]


def test_main_rejects_bad_options(capsys):
    for argv in (["--max-calls", "5"], ["--only", "nope"], ["--json", "--md"]):
        with pytest.raises(SystemExit) as e:
            ev.main(argv)
        assert e.value.code == 2
    assert ev.main(["--live", "--max-calls", "500"]) == 2  # 上限を超える指定は呼ぶ前に断る
    assert "上限" in capsys.readouterr().err


def test_a_skipped_row_renders_without_numbers():
    table = {"live": True, "calls_used": 3, "calls_limit": 3, "rows": [measure.skipped_row(gen.VARIANTS[0], InspectMode.ROUTER, "m", "上限")],
             "totals": measure.totals([])}  # fmt: skip
    md = measure.to_markdown(table)
    assert "| v1clean | router | m | skipped |" in md and "3 / 上限 3 回" in md
