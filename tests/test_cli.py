"""app/cli.py: プリセットIDだけを受け、フェイクの取得・モデルで完全オフラインに動く。出力は JSON／HTML・トレースは JSONL。"""
import io
import json

import pytest

from app.cli import main
from app.config import PRESET_IDS, Settings
from app.contracts import CheckClass, FetchMode, Kind
from app.model.scripted import ScriptedPort
from tests.agent_support import (
    AUTH_SENTENCE,
    LEN_SENTENCE,
    LOGIN_HTML,
    LOGIN_URL,
    SPEC_HTML,
    SUBMISSION_HTML,
    RoutedFetch,
    raw,
    reader_reply,
    standard_planner,
    standard_reader,
)
from tests.fetch_fakes import SUB_URL, make_result, redirect

SETTINGS = Settings(self_origin="https://svc.example.invalid")  # sample_defect の取得先が svc.example.invalid/fx/defect/ になる
CLI_SPEC_URL = "https://svc.example.invalid/fx/defect/spec/"
CLI_FAQ_URL = "https://svc.example.invalid/fx/defect/faq/"  # 第3弾: 要項は2ページ（spec/・faq/）
CLI_APP_URL = "https://svc.example.invalid/fx/defect/app/"  # 第3弾: デプロイURL（SUBMISSION_URL）。説明ページは submission/


def cli_fetch() -> RoutedFetch:
    return RoutedFetch(
        {
            (CLI_SPEC_URL, FetchMode.PAGE): make_result(CLI_SPEC_URL, body=SPEC_HTML),
            (CLI_FAQ_URL, FetchMode.PAGE): make_result(CLI_FAQ_URL, body="<html><body><p>よくある質問はありません。</p></body></html>"),
            (SUB_URL, FetchMode.PAGE): make_result(SUB_URL, body=SUBMISSION_HTML),
            (CLI_APP_URL, FetchMode.PROBE): make_result(
                CLI_APP_URL, redirects=(redirect(frm=CLI_APP_URL),), final_url=LOGIN_URL, body=LOGIN_HTML
            ),
        }
    )


def run_cli(argv, *, reader=None, planner=None, fetch=None):
    out, err = io.StringIO(), io.StringIO()
    # 要項は2ページ（spec/・faq/）なので Reader は2回呼ばれる。2回目（FAQ）は要件なしの応答
    code = main(argv, fetch=fetch or cli_fetch(), reader_model=reader or standard_reader(reader_reply()), planner_model=planner,
                settings=SETTINGS, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_router_mode_prints_the_json_record():
    code, out, err = run_cli(["sample_defect", "--inspect-mode", "router"])
    assert (code, err) == (0, "")
    rec = json.loads(out)
    assert rec["status"] == "DONE" and rec["preset_id"] == "sample_defect" and rec["planner_model"] == "router"
    assert [v["label"] for v in rec["verdicts"]] == ["不適合", "不適合"]
    assert rec["requirements"][0]["span"]["original_span"] == LEN_SENTENCE


def test_planner_mode_with_a_scripted_planner():
    code, out, _ = run_cli(["sample_defect"], planner=standard_planner())
    assert code == 0 and json.loads(out)["planner_model"] == "scripted-planner"


def test_html_format_and_output_files(tmp_path):
    out_file, trace_file = tmp_path / "report.html", tmp_path / "trace.jsonl"
    code, out, _ = run_cli(["sample_defect", "--inspect-mode", "router", "--format", "html", "--out", str(out_file), "--trace", str(trace_file)])
    assert code == 0 and out == ""  # --out の時は標準出力へ出さない
    html = out_file.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>") and "<table" in html and AUTH_SENTENCE in html
    lines = trace_file.read_text(encoding="utf-8").splitlines()
    events = [json.loads(x) for x in lines]
    assert events[0]["type"] == "phase_enter" and events[0]["name"] == "ACQUIRE" and events[-1]["name"] == "DONE"
    assert len({e["run_id"] for e in events}) == 1


def test_only_preset_ids_are_accepted_never_a_url(capsys):
    for bad in ("https://evil.invalid/", "../etc/passwd", "lp_self; rm -rf /"):
        with pytest.raises(SystemExit) as e:
            main([bad], settings=SETTINGS)
        assert e.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert set(PRESET_IDS) == {"lp_self", "sample_defect", "sample_injection"}


def test_inspect_mode_is_validated():
    with pytest.raises(SystemExit):
        main(["sample_defect", "--inspect-mode", "auto"], settings=SETTINGS)


def test_kill_switch_exits_with_2_and_still_prints_an_aborted_record():
    out, err = io.StringIO(), io.StringIO()
    code = main(["sample_defect", "--inspect-mode", "router"], fetch=cli_fetch(), reader_model=standard_reader(),
                settings=Settings(self_origin="https://svc.example.invalid", kill_switch=True), stdout=out, stderr=err)
    assert code == 2 and json.loads(out.getvalue())["status"] == "ABORTED"


def test_a_degraded_run_exits_0_and_says_so():
    reader = ScriptedPort([reader_reply(raw(LEN_SENTENCE, Kind.REQUIRED, CheckClass.LENGTH_LIMIT))])
    from app.errors import AppError, ErrorCode

    code, out, _ = run_cli(["sample_defect", "--inspect-mode", "router"], reader=ScriptedPort([AppError(ErrorCode.RETRYABLE, "x")]))
    assert code == 0 and json.loads(out)["status"] == "DEGRADED"
    assert reader.requests == []


def test_a_config_error_prints_only_the_public_code_and_message(clean_env):
    """GOOGLE_CLOUD_PROJECT が無い（Vertex を使えない）。例外の文面・設定値は出さず、固定文だけを出す。"""
    out, err = io.StringIO(), io.StringIO()
    code = main(["sample_defect", "--inspect-mode", "router"], fetch=cli_fetch(), settings=SETTINGS, stdout=out, stderr=err)
    assert code == 1 and out.getvalue() == ""
    assert err.getvalue().strip() == "FATAL_CONFIG: ライブ実行を一時的に停止しています。"
    assert "GOOGLE_CLOUD_PROJECT" not in err.getvalue()


def test_module_entry_point_exists():
    import app.cli as cli

    assert callable(cli.main) and cli.__name__ == "app.cli"
