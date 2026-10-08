"""プリセットの読める要項・提出物と「仕込んだ場所 → 見つけた結果」（app/web/examples.py と /api/status）。"""
import copy
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import PRESET_IDS, PRESET_LP_SELF, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION, Settings, build_presets
from app.fixtures.gen import EXPECTED_PATH
from app.fixtures.site import FixtureSite
from app.web.app import create_app
from app.web.examples import FICTIONAL_NOTE, PLANTED_TEXT, ExamplesError, build_examples
from app.web.replay import REPLAY_DIR

SELF = "https://self.example.invalid"
SETTINGS = Settings(self_origin=SELF)
PRESETS = build_presets(SETTINGS)
EXPECTED = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
FX = (PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION)


def test_fixture_links_resolve_to_200_and_guide_is_only_in_preset_2():
    site = FixtureSite.load()
    ex = build_examples(PRESETS)
    for pid in FX:
        roles = [ln["role"] for ln in ex[pid]["links"]]
        assert roles == (["spec", "faq", "submission", "guide", "login"] if pid == PRESET_SAMPLE_DEFECT else ["spec", "faq", "submission", "login"])
        for ln in ex[pid]["links"]:
            assert ln["href"].startswith("/fx/") and site.resolve(ln["href"]).status == 200
        assert not any(ln["href"].endswith("/app/") for ln in ex[pid]["links"])  # app/ は転送


def test_fictional_flags_and_planted_rows():
    ex = build_examples(PRESETS)
    assert ex[PRESET_LP_SELF]["fictional"] is False and ex[PRESET_LP_SELF]["fictional_note"] is None
    assert ex[PRESET_LP_SELF]["planted"] == []
    for pid in FX:
        assert ex[pid]["fictional"] is True and ex[pid]["fictional_note"] == FICTIONAL_NOTE
    d = {r["id"]: r for r in ex[PRESET_SAMPLE_DEFECT]["planted"]}
    assert list(d) == ["D1", "D2", "D3", "D4", "G1"]
    assert d["D1"]["found"] == {"kind": "verdict", "req_id": "R2", "label": "不適合"}
    assert d["D4"]["found"] == {"kind": "contradiction", "slot": "締切", "req_ids": ["R1", "R8"]}
    assert d["G1"]["found"]["label"] == "推定適合"
    i = {r["id"]: r for r in ex[PRESET_SAMPLE_INJECTION]["planted"]}
    assert list(i) == ["D1", "D2", "D3", "D4", "INJ_VISIBLE", "INJ_HIDDEN"]
    assert i["INJ_VISIBLE"]["found"]["count"] >= 2 and i["INJ_HIDDEN"]["found"]["count"] >= 1
    for rows in (d, i):
        for r in rows.values():
            assert (r["summary_ja"], r["where_ja"]) == PLANTED_TEXT[r["id"]]


def test_planted_rows_match_expected_labels():
    ex = build_examples(PRESETS)
    for pid in FX:
        for dfc in EXPECTED["presets"][pid]["defects"]:
            row = next(r for r in ex[pid]["planted"] if r["id"] == dfc["id"])
            if dfc["type"] == "verdict":
                assert row["found"]["label"] == dfc["label"]


def test_preset_1_links_are_the_preset_urls_and_carry_no_spec_text():
    ex = build_examples(PRESETS)[PRESET_LP_SELF]
    p = PRESETS[PRESET_LP_SELF]
    off = [ln for ln in ex["links"] if ln["role"] == "official"]
    assert [ln["href"] for ln in off] == list(p.spec_seed_urls) and 1 <= len(off) <= 3
    assert [ln["href"] for ln in ex["links"] if ln["role"] == "submission"] == [p.submission_url]
    assert all(len(ln["label_ja"]) <= 40 for ln in ex["links"])
    assert {ln["label_ja"] for ln in ex["links"]} == {"募集ページ（外部サイトが開きます）", "提出物（このサービス自身）"}


def test_status_response_shape():
    r = TestClient(create_app(SETTINGS)).get("/api/status")
    data = r.json()
    assert [p["id"] for p in data["presets"]] == list(PRESET_IDS)
    for p in data["presets"]:
        assert set(p) == {"id", "label", "kind", "replay", "fictional", "fictional_note", "links", "planted"}
    by = {p["id"]: p for p in data["presets"]}
    assert by[PRESET_LP_SELF]["planted"] == [] and by[PRESET_LP_SELF]["fictional"] is False
    assert [ln["href"] for ln in by[PRESET_LP_SELF]["links"]] == [*PRESETS[PRESET_LP_SELF].spec_seed_urls, PRESETS[PRESET_LP_SELF].submission_url]
    assert by[PRESET_SAMPLE_DEFECT]["planted"][0]["id"] == "D1"
    shown = json.dumps([{k: p[k] for k in ("fictional_note", "links", "planted")} for p in data["presets"]], ensure_ascii=False)
    for word in ("AUTORUN", "Planner", "Governor", "REPLAY", "oracle", "Oracle"):
        assert word not in shown


def test_status_has_no_secrets_or_internal_urls():
    from app.checks.leak_scan import LEAK_PATTERNS

    text = TestClient(create_app(SETTINGS)).get("/api/status").text
    # ①の href は設定の値（プレースホルダ）をそのまま通すので、内部URL・メールの形だけは links の外で確かめる
    data = json.loads(text)
    for p in data["presets"]:
        p["links"] = [ln for ln in p["links"] if ln["href"].startswith("/fx/")]
    rest = json.dumps(data, ensure_ascii=False)
    for name, pat in LEAK_PATTERNS.items():
        assert not pat.search(rest), name


# ---- 負例: 記録と正解表のどちらを壊しても起動時に落ちる -------------------------------------------
@pytest.fixture
def replay_copy(tmp_path: Path) -> Path:
    shutil.copytree(REPLAY_DIR, tmp_path / "r")
    return tmp_path / "r"


def _edit(path: Path, fn) -> None:  # noqa: ANN001
    d = json.loads(path.read_text(encoding="utf-8"))
    fn(d)
    path.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")


def test_broken_expected_label_fails():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][0]["label"] = "適合"
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, expected=bad)


def test_unknown_expected_quote_fails():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][1]["quote"] = "存在しない引用"
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, expected=bad)


def test_expected_contradiction_missing_from_record_fails():
    bad = copy.deepcopy(EXPECTED)
    bad["presets"][PRESET_SAMPLE_DEFECT]["defects"][3]["tokens"] = ["1", "2"]
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, expected=bad)


def test_record_without_injection_signals_fails(replay_copy: Path):
    _edit(replay_copy / f"{PRESET_SAMPLE_INJECTION}.json", lambda d: d.update(injection_signals=[]))
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, replay_dir=replay_copy)


def test_record_with_changed_verdict_fails(replay_copy: Path):
    def flip(d: dict) -> None:
        for v in d["verdicts"]:
            if v["label"] == "不適合":
                v.update(label="確認不能", reason_code="no_observation", evidence=[])
                break

    _edit(replay_copy / f"{PRESET_SAMPLE_DEFECT}.json", flip)
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, replay_dir=replay_copy)


def test_missing_record_fails(replay_copy: Path):
    (replay_copy / f"{PRESET_SAMPLE_DEFECT}.json").unlink()
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, replay_dir=replay_copy)


def test_link_not_returning_200_fails():
    with pytest.raises(ExamplesError):
        build_examples(PRESETS, site=FixtureSite({}))
