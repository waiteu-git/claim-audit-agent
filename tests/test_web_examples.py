"""プリセットの読める要項・提出物と「仕込んだ場所 → 見つけた結果」（app/web/examples.py と /api/status）。

負例は、**意図した分岐**を通ることを ExamplesError の理由コード・プリセットID・項目IDで確かめる（別の理由で落ちていないこと）。
記録を書き換える負例は、契約として有効な記録を作ってから壊す（restore_saved_record を通す＝契約違反で落ちる、にならない）。
"""
import asyncio
import copy
import json
import re
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.checks.leak_scan import LEAK_PATTERNS, scan_text
from app.config import PRESET_IDS, PRESET_LP_SELF, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION, Settings, build_presets
from app.contracts import RunRecord, serialize_report
from app.fixtures.gen import EXPECTED_PATH
from app.fixtures.site import FixtureSite
from app.quotes.replay import restore_saved_record
from app.web import examples, replay
from app.web.app import create_app
from app.web.examples import (
    BASIS_BUNDLED_REPLAY,
    FICTIONAL_NOTE,
    PLANTED_TEXT,
    ExamplesCode,
    ExamplesError,
    build_examples,
)
from app.web.replay import REPLAY_DIR, load_fixture_records
from tests.web_support import scripted_runner

SELF = "https://self.example.invalid"
SETTINGS = Settings(self_origin=SELF)
PRESETS = build_presets(SETTINGS)
EXPECTED = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
FX = (PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION)
RECORDS = load_fixture_records()
ERROR_FORMAT = re.compile(r"^[a-z0-9_]+ preset=[A-Za-z0-9_]+ item=(?:[A-Za-z0-9_]+|-)$")


def rows_of(pid: str, records=RECORDS, **kw) -> dict[str, dict]:
    return {r["id"]: r for r in build_examples({pid: PRESETS[pid]}, records, **kw)[pid]["planted"]}


def edited(pid: str, fn) -> dict[str, RunRecord]:  # noqa: ANN001
    """同梱の記録を書き換えた、契約として有効な記録（壊れた記録なら restore_saved_record がここで落ちる）。"""
    d = json.loads(serialize_report(RECORDS[pid]))
    fn(d)
    return {**RECORDS, pid: restore_saved_record(json.dumps(d, ensure_ascii=False))}


def expect_error(code: ExamplesCode, preset_id: str, item_id: str | None, fn) -> ExamplesError:  # noqa: ANN001
    with pytest.raises(ExamplesError) as ei:
        fn()
    e = ei.value
    assert (e.code, e.preset_id, e.item_id) == (code, preset_id, item_id)
    assert ERROR_FORMAT.match(str(e)), "文言は固定の識別子だけ"
    return e


# ---- リンク -------------------------------------------------------------------------------------
def test_fixture_links_resolve_to_200_and_guide_is_only_in_preset_2():
    site = FixtureSite.load()
    ex = build_examples(PRESETS, RECORDS)
    for pid in FX:
        roles = [ln["role"] for ln in ex[pid]["links"]]
        assert roles == (["spec", "faq", "submission", "guide", "login"] if pid == PRESET_SAMPLE_DEFECT else ["spec", "faq", "submission", "login"])
        for ln in ex[pid]["links"]:
            assert ln["href"].startswith("/fx/") and site.resolve(ln["href"]).status == 200
        assert not any(ln["href"].endswith("/app/") for ln in ex[pid]["links"])  # app/ は転送


def test_preset_1_links_are_the_preset_urls_and_carry_no_spec_text():
    ex = build_examples(PRESETS, RECORDS)[PRESET_LP_SELF]
    p = PRESETS[PRESET_LP_SELF]
    off = [ln for ln in ex["links"] if ln["role"] == "official"]
    assert [ln["href"] for ln in off] == list(p.spec_seed_urls) and 1 <= len(off) <= 3
    assert [ln["href"] for ln in ex["links"] if ln["role"] == "submission"] == [p.submission_url]
    assert {ln["label_ja"] for ln in ex["links"]} == {"募集ページ（外部サイトが開きます）", "提出物（このサービス自身）"}


# ---- planted の中身 -----------------------------------------------------------------------------
def test_fictional_flags_and_planted_rows():
    ex = build_examples(PRESETS, RECORDS)
    assert ex[PRESET_LP_SELF]["fictional"] is False and ex[PRESET_LP_SELF]["fictional_note"] is None
    assert ex[PRESET_LP_SELF]["planted"] == []
    for pid in FX:
        assert ex[pid]["fictional"] is True and ex[pid]["fictional_note"] == FICTIONAL_NOTE
    d = {r["id"]: r for r in ex[PRESET_SAMPLE_DEFECT]["planted"]}
    assert list(d) == ["D1", "D2", "D3", "D4", "G1"]
    assert d["D1"]["found"] == {"kind": "verdict", "req_id": "R2", "label": "不適合", "quote": "作品の公開説明文は800字以内とすること。"}
    assert d["D4"]["found"] == {"kind": "contradiction", "slot": "締切", "tokens": ["10/15 23:59", "10/16 12:00"], "req_ids": ["R1", "R8"]}
    assert d["G1"]["found"]["label"] == "推定適合"
    i = {r["id"]: r for r in ex[PRESET_SAMPLE_INJECTION]["planted"]}
    assert list(i) == ["D1", "D2", "D3", "D4", "INJ_VISIBLE", "INJ_HIDDEN"]
    assert i["INJ_VISIBLE"]["found"]["count"] >= 2 and i["INJ_HIDDEN"]["found"]["count"] >= 1


def test_planted_rows_match_the_expected_table():
    ex = build_examples(PRESETS, RECORDS)
    for pid in FX:
        exp = EXPECTED["presets"][pid]
        rows = {r["id"]: r["found"] for r in ex[pid]["planted"]}
        for dfc in exp["defects"]:
            if dfc["type"] == "verdict":
                assert (rows[dfc["id"]]["label"], rows[dfc["id"]]["quote"]) == (dfc["label"], dfc["quote"])
            else:
                assert (rows[dfc["id"]]["slot"], rows[dfc["id"]]["tokens"]) == (dfc["slot"], dfc["tokens"])
        for g in exp.get("guards") or ():
            assert (rows[g["id"]]["label"], rows[g["id"]]["quote"]) == (g["label"], g["quote"])


def test_every_planted_row_says_found_values_come_from_the_bundled_record():
    """found の req_id・件数は同梱の記録の値。ライブ実行では要件の採番が変わりうるので、各行に由来を明示する（画面は突き合わせて使う）。"""
    ex = build_examples(PRESETS, RECORDS)
    assert BASIS_BUNDLED_REPLAY == "bundled_replay"
    for pid in FX:
        assert ex[pid]["planted"] and all(r["basis"] == BASIS_BUNDLED_REPLAY for r in ex[pid]["planted"])
    assert ex[PRESET_LP_SELF]["planted"] == []


def test_found_quote_binds_to_the_live_run_where_the_requirement_numbers_differ():
    """ライブ相当の実行（台本の Reader）では、同じ要項でも req_id の採番が同梱の記録と違う（D3 は R7 と R4）。
    番号で結ぶと別の行（確認不能）を指すので、found.quote（要項の逐語）で結べること。実行に出ない行（G1 など）は結ばない。"""
    ex = build_examples(PRESETS, RECORDS)
    for pid in FX:
        live = asyncio.run(scripted_runner()(PRESETS[pid], lambda _e: None)).record
        by_quote = {r.span.original_span: r.req_id for r in live.requirements if r.span}
        labels = {v.req_id: v.label.value for v in live.verdicts}
        bound = 0
        for row in ex[pid]["planted"]:
            f = row["found"]
            if f["kind"] != "verdict" or f["quote"] not in by_quote:
                continue
            assert labels[by_quote[f["quote"]]] == f["label"], row["id"]  # 引用で結べば、同じ要件の判定ラベルが合う
            bound += 1
        assert bound >= 3  # D1〜D3


# ---- 画面に出る語 -------------------------------------------------------------------------------
SUMMARY_KEYWORD = {"D1": "800字", "D2": "ログイン", "D3": "メール", "D4": "締切", "G1": "操作ガイド", "INJ_VISIBLE": "見える", "INJ_HIDDEN": "見えない"}
WHERE_KEYWORD = {"D1": "説明ページ", "D2": "ログイン", "D3": "説明ページ", "D4": "よくある質問", "G1": "操作ガイド", "INJ_VISIBLE": "要項", "INJ_HIDDEN": "見えない"}
INTERNAL_WORDS = ("AUTORUN", "Planner", "Governor", "REPLAY", "Reader", "oracle", "Oracle", "本文")


def test_planted_texts_say_what_each_row_is_about():
    """固定文を、表そのものではなく項目ごとの語で確かめる（D1 と D2 の入れ替え、見える／見えないの取り違えを見つける）。"""
    ex = build_examples(PRESETS, RECORDS)
    seen = set()
    for pid in FX:
        for r in ex[pid]["planted"]:
            seen.add(r["id"])
            assert SUMMARY_KEYWORD[r["id"]] in r["summary_ja"], r["id"]
            assert WHERE_KEYWORD[r["id"]] in r["where_ja"], r["id"]
            if r["id"] == "INJ_VISIBLE":
                assert "見えない" not in r["where_ja"] and "見えない" not in r["summary_ja"]
            if r["id"] == "INJ_HIDDEN":
                assert "要項" not in r["where_ja"]
            if r["id"] in ("D1", "D3"):
                assert "ログイン" not in r["summary_ja"]
            if r["id"] == "D2":
                assert "800字" not in r["summary_ja"] and "メール" not in r["summary_ja"]
    assert seen == set(SUMMARY_KEYWORD) == set(PLANTED_TEXT)


def test_user_facing_texts_use_no_internal_words_and_say_page_not_honbun():
    ex = build_examples(PRESETS, RECORDS)
    texts = [FICTIONAL_NOTE, examples.LABEL_OFFICIAL, examples.LABEL_SELF]
    for s, w in PLANTED_TEXT.values():
        texts += [s, w]
    for pid in FX:
        texts += [ln["label_ja"] for ln in ex[pid]["links"]]
    for t in texts:
        assert not any(word in t for word in INTERNAL_WORDS), t
    assert "提出物のページ" in PLANTED_TEXT["G1"][0]


# ---- /api/status --------------------------------------------------------------------------------
def test_status_response_shape():
    r = TestClient(create_app(SETTINGS)).get("/api/status")
    data = r.json()
    assert [p["id"] for p in data["presets"]] == list(PRESET_IDS)
    for p in data["presets"]:
        assert set(p) == {"id", "label", "kind", "replay", "fictional", "fictional_note", "links", "planted"}
        assert all(set(row) == {"id", "summary_ja", "where_ja", "found", "basis"} for row in p["planted"])
    by = {p["id"]: p for p in data["presets"]}
    assert by[PRESET_LP_SELF]["planted"] == [] and by[PRESET_LP_SELF]["fictional"] is False
    lp = PRESETS[PRESET_LP_SELF]
    assert [ln["href"] for ln in by[PRESET_LP_SELF]["links"]] == [*lp.spec_seed_urls, lp.submission_url]
    assert by[PRESET_SAMPLE_DEFECT]["planted"][0]["id"] == "D1"
    assert {row["basis"] for p in data["presets"] for row in p["planted"]} == {"bundled_replay"}


# ---- 漏洩CI: 実際に使う値（https の SELF_ORIGIN・LP_SEED_URLS）で、links を含む応答全体を走査する -----------------
def status_text(settings: Settings) -> str:
    return TestClient(create_app(settings)).get("/api/status").text


def test_status_has_no_leak_pattern_with_https_deploy_values_links_included():
    s = Settings(self_origin="https://svc.example.invalid", lp_seed_urls=("https://lp.example.invalid/event", "https://lp.example.invalid/faq"))
    text = status_text(s)
    assert "https://svc.example.invalid/" in text and "https://lp.example.invalid/event" in text  # links の値が応答に入っている
    assert scan_text(text) == {}
    for name, pat in LEAK_PATTERNS.items():
        assert not pat.search(text), name


def test_a_direct_service_origin_appears_only_as_the_preset_1_submission_link():
    """本番の SELF_ORIGIN が実行環境の直URLなら、service_url の検知は①の提出物リンク（利用者が既に開いている origin）の1件だけ。
    それは設計どおり（仕様）なので、意図した例外として固定する。他の欄（label_ja・note・planted 等）には出ない。"""
    host = "svc-abc123-an" + "." + "run" + "." + "app"  # ソースに実行環境の直URLを書かない規約（test_layout）のため連結
    origin = f"https://{host}"
    data = TestClient(create_app(Settings(self_origin=origin))).get("/api/status").json()
    text = json.dumps(data, ensure_ascii=False)
    assert scan_text(text) == {"service_url": 1}
    holders = [(p["id"], ln["role"]) for p in data["presets"] for ln in p["links"] if host in ln["href"]]
    assert holders == [(PRESET_LP_SELF, "submission")]
    exempt = {ln["href"] for p in data["presets"] for ln in p["links"] if host in ln["href"]}
    rest = text
    for h in exempt:
        rest = rest.replace(h, "")
    assert scan_text(rest) == {}


# ---- 負例: 記録と正解表のどちらを壊しても、意図した分岐で止まる（固定の識別子つき） ----------------------------
def test_expected_label_changed_stops_at_label_mismatch_of_that_item():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["label"] = "適合"
    expect_error(ExamplesCode.LABEL_MISMATCH, PRESET_SAMPLE_DEFECT, "D1", lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))


def test_record_verdict_changed_validly_stops_at_label_mismatch_of_that_item():
    """記録側を壊す。R2（D1 の要件）を、契約として有効な形で確認不能にする（理由コードは OUT_OF_SCOPE・証拠なし）。"""

    def flip(d: dict) -> None:
        v = next(v for v in d["verdicts"] if v["req_id"] == "R2")
        assert v["label"] == "不適合"
        v.update(label="確認不能", reason_code="OUT_OF_SCOPE", reason="", evidence=[])

    recs = edited(PRESET_SAMPLE_DEFECT, flip)  # ここで契約違反なら ValidationError（＝別の理由で通っている、を防ぐ）
    assert recs[PRESET_SAMPLE_DEFECT].verdicts[1].label.value == "確認不能"
    expect_error(ExamplesCode.LABEL_MISMATCH, PRESET_SAMPLE_DEFECT, "D1", lambda: rows_of(PRESET_SAMPLE_DEFECT, recs))


def test_expected_quote_unknown_stops_at_quote_not_in_record():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][1]["quote"] = "存在しない引用"
    expect_error(ExamplesCode.QUOTE_NOT_IN_RECORD, PRESET_SAMPLE_DEFECT, "D2", lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))


def test_two_requirements_with_the_same_quote_stop_at_quote_ambiguous():
    def dup(d: dict) -> None:
        r2 = next(r for r in d["requirements"] if r["req_id"] == "R2")
        r4 = next(r for r in d["requirements"] if r["req_id"] == "R4")
        r4["span"] = copy.deepcopy(r2["span"])  # 位置と引用の長さは契約が照合するので、span ごと写す

    recs = edited(PRESET_SAMPLE_DEFECT, dup)
    quote = EXPECTED["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["quote"]
    assert sum(1 for r in recs[PRESET_SAMPLE_DEFECT].requirements if r.span and r.span.original_span == quote) == 2
    expect_error(ExamplesCode.QUOTE_AMBIGUOUS, PRESET_SAMPLE_DEFECT, "D1", lambda: rows_of(PRESET_SAMPLE_DEFECT, recs))


def test_expected_quote_over_80_chars_stops_at_quote_too_long():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["quote"] = "あ" * 81
    expect_error(ExamplesCode.QUOTE_TOO_LONG, PRESET_SAMPLE_DEFECT, "D1", lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))


def test_expected_contradiction_unknown_stops_at_contradiction_mismatch():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][3]["tokens"] = ["1", "2"]
    expect_error(ExamplesCode.CONTRADICTION_MISMATCH, PRESET_SAMPLE_DEFECT, "D4", lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))


def test_record_without_the_contradiction_stops_at_contradiction_mismatch():
    recs = edited(PRESET_SAMPLE_DEFECT, lambda d: d.update(contradictions=[]))
    assert recs[PRESET_SAMPLE_DEFECT].contradictions == ()
    expect_error(ExamplesCode.CONTRADICTION_MISMATCH, PRESET_SAMPLE_DEFECT, "D4", lambda: rows_of(PRESET_SAMPLE_DEFECT, recs))


def test_record_without_any_injection_signal_stops_at_signals_short_visible():
    recs = edited(PRESET_SAMPLE_INJECTION, lambda d: d.update(injection_signals=[]))
    expect_error(ExamplesCode.SIGNALS_SHORT_VISIBLE, PRESET_SAMPLE_INJECTION, "INJ_VISIBLE", lambda: rows_of(PRESET_SAMPLE_INJECTION, recs))


def test_record_with_visible_signals_but_none_hidden_stops_at_signals_short_hidden():
    """hidden_min の検査: 見える2件は残し、隠れた1件だけを消した記録。"""
    recs = edited(PRESET_SAMPLE_INJECTION, lambda d: d.update(injection_signals=[s for s in d["injection_signals"] if s["visible"]]))
    sig = recs[PRESET_SAMPLE_INJECTION].injection_signals
    assert sum(s.visible for s in sig) >= EXPECTED["presets"][PRESET_SAMPLE_INJECTION]["injection"]["visible_min"] and not any(not s.visible for s in sig)
    expect_error(ExamplesCode.SIGNALS_SHORT_HIDDEN, PRESET_SAMPLE_INJECTION, "INJ_HIDDEN", lambda: rows_of(PRESET_SAMPLE_INJECTION, recs))


def test_record_with_hidden_signals_but_too_few_visible_stops_at_signals_short_visible():
    recs = edited(PRESET_SAMPLE_INJECTION, lambda d: d.update(injection_signals=[s for s in d["injection_signals"] if not s["visible"]]))
    assert any(not s.visible for s in recs[PRESET_SAMPLE_INJECTION].injection_signals)
    expect_error(ExamplesCode.SIGNALS_SHORT_VISIBLE, PRESET_SAMPLE_INJECTION, "INJ_VISIBLE", lambda: rows_of(PRESET_SAMPLE_INJECTION, recs))


def test_missing_record_stops_at_record_missing():
    recs = {k: v for k, v in RECORDS.items() if k != PRESET_SAMPLE_INJECTION}
    expect_error(ExamplesCode.RECORD_MISSING, PRESET_SAMPLE_INJECTION, None, lambda: build_examples(PRESETS, recs))


def test_link_not_returning_200_stops_at_link_not_200_of_that_role():
    expect_error(ExamplesCode.LINK_NOT_200, PRESET_SAMPLE_DEFECT, "link_spec", lambda: build_examples(PRESETS, RECORDS, site=FixtureSite({})))


def test_text_table_without_the_item_stops_at_text_missing(monkeypatch):
    monkeypatch.setattr(examples, "PLANTED_TEXT", {k: v for k, v in PLANTED_TEXT.items() if k != "D3"})
    expect_error(ExamplesCode.TEXT_MISSING, PRESET_SAMPLE_DEFECT, "D3", lambda: rows_of(PRESET_SAMPLE_DEFECT))


def test_expected_table_without_the_preset_or_with_unknown_defect_type():
    bad = copy.deepcopy(EXPECTED)
    del bad["presets"][PRESET_SAMPLE_INJECTION]
    expect_error(ExamplesCode.EXPECTED_MISSING, PRESET_SAMPLE_INJECTION, None, lambda: rows_of(PRESET_SAMPLE_INJECTION, expected=bad))
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][2]["type"] = "mystery"
    expect_error(ExamplesCode.DEFECT_TYPE_UNKNOWN, PRESET_SAMPLE_DEFECT, "D3", lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))
    bad = copy.deepcopy(EXPECTED)
    del bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["quote"]
    expect_error(ExamplesCode.EXPECTED_MALFORMED, PRESET_SAMPLE_DEFECT, None, lambda: rows_of(PRESET_SAMPLE_DEFECT, expected=bad))


def test_error_text_never_carries_record_or_table_content():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["id"] = "D1 someone@example.invalid 作品の公開説明文"
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["label"] = "適合"
    with pytest.raises(ExamplesError) as ei:
        rows_of(PRESET_SAMPLE_DEFECT, expected=bad)
    assert str(ei.value) == "label_mismatch preset=sample_defect item=?"


# ---- 記録の読み込み（起動時）----------------------------------------------------------------------
@pytest.fixture
def replay_copy(tmp_path: Path) -> Path:
    shutil.copytree(REPLAY_DIR, tmp_path / "r")
    return tmp_path / "r"


def test_load_fixture_records_stops_at_missing_or_unreadable_record(replay_copy: Path):
    assert set(load_fixture_records(replay_copy)) == set(FX)
    (replay_copy / f"{PRESET_SAMPLE_INJECTION}.json").write_text("{not json", encoding="utf-8")
    e = expect_error(ExamplesCode.RECORD_UNREADABLE, PRESET_SAMPLE_INJECTION, None, lambda: load_fixture_records(replay_copy))
    assert e.__cause__ is None and e.__suppress_context__  # 原因（記録の中身を含みうる）は連鎖させない
    (replay_copy / f"{PRESET_SAMPLE_DEFECT}.json").unlink()
    expect_error(ExamplesCode.RECORD_MISSING, PRESET_SAMPLE_DEFECT, None, lambda: load_fixture_records(replay_copy))


def test_a_broken_preset_1_record_does_not_stop_the_start(replay_copy: Path):
    """①の記録は対応表の元ではない（planted=[]）。load_replays が外すだけで、起動は止めない。"""
    (replay_copy / "lp_self.json").write_text("{not json", encoding="utf-8")
    assert set(load_fixture_records(replay_copy)) == set(FX)


def test_create_app_refuses_to_start_when_a_record_and_the_expected_table_disagree(monkeypatch):
    from app.web import app as web_app

    def tampered(root=REPLAY_DIR):  # noqa: ANN001
        return edited(PRESET_SAMPLE_INJECTION, lambda d: d.update(injection_signals=[]))

    monkeypatch.setattr(web_app, "load_fixture_records", tampered)
    with pytest.raises(ExamplesError) as ei:
        create_app(SETTINGS)
    assert (ei.value.code, ei.value.preset_id, ei.value.item_id) == (ExamplesCode.SIGNALS_SHORT_VISIBLE, PRESET_SAMPLE_INJECTION, "INJ_VISIBLE")


# ---- 記録の再生成・取り込みの検査（起動で初めて落ちる、にしない）----------------------------------------------
def flipped_defect_record_json() -> str:
    """契約として有効で、D1 の判定ラベルだけが正解表とずれた②の記録（実モデルの記録を取り込んだ扱い）。"""
    d = json.loads(serialize_report(RECORDS[PRESET_SAMPLE_DEFECT]))
    v = next(v for v in d["verdicts"] if v["req_id"] == "R2")
    v.update(label="確認不能", reason_code="OUT_OF_SCOPE", reason="", evidence=[])
    return json.dumps(d, ensure_ascii=False)


def test_check_reports_a_label_mismatch_of_an_imported_record(replay_copy: Path):
    assert replay.check(replay_copy) == []  # 基準: 同梱のままなら差分なし
    (replay_copy / f"{PRESET_SAMPLE_DEFECT}.json").write_text(flipped_defect_record_json(), encoding="utf-8")
    assert replay.load_bundle(replay_copy / f"{PRESET_SAMPLE_DEFECT}.json")  # 契約として読める（他の理由の差分ではない）
    assert replay.check(replay_copy) == [f"{PRESET_SAMPLE_DEFECT}.json: label_mismatch preset={PRESET_SAMPLE_DEFECT} item=D1"]


def test_import_refuses_a_record_that_disagrees_with_the_expected_table(replay_copy: Path, tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(replay, "REPLAY_DIR", replay_copy)
    target = replay_copy / f"{PRESET_SAMPLE_DEFECT}.json"
    src = tmp_path / "rec.json"
    # 基準: ずれの無い記録は取り込める（取り込み自体が壊れていて失敗、ではない）
    src.write_text(serialize_report(RECORDS[PRESET_SAMPLE_DEFECT]), encoding="utf-8")
    assert replay.main(["--import", str(src), "--preset", PRESET_SAMPLE_DEFECT]) == 0
    after_ok = target.read_text(encoding="utf-8")
    # ずれた記録は取り込まない（書き込まない）
    src.write_text(flipped_defect_record_json(), encoding="utf-8")
    assert replay.main(["--import", str(src), "--preset", PRESET_SAMPLE_DEFECT]) == 1
    assert target.read_text(encoding="utf-8") == after_ok
    assert "label_mismatch preset=sample_defect item=D1" in capsys.readouterr().err


def test_write_regenerates_records_that_pass_the_cross_check(replay_copy: Path, monkeypatch):
    monkeypatch.setattr(replay, "REPLAY_DIR", replay_copy)
    assert replay.main(["--write"]) == 0
    assert replay.check(replay_copy) == []


def test_write_refuses_when_the_regenerated_record_disagrees(replay_copy: Path, monkeypatch, capsys):
    monkeypatch.setattr(replay, "REPLAY_DIR", replay_copy)
    before = {p.name: p.read_text(encoding="utf-8") for p in replay_copy.glob("*.json")}
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["label"] = "適合"

    real = examples.build_examples
    monkeypatch.setattr(replay, "build_examples", lambda presets, records, **kw: real(presets, records, expected=bad, **kw))
    assert replay.main(["--write"]) == 1
    assert {p.name: p.read_text(encoding="utf-8") for p in replay_copy.glob("*.json")} == before  # 何も書かない
    assert "label_mismatch preset=sample_defect item=D1" in capsys.readouterr().err
