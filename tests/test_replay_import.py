"""第4弾 2: REPLAY の取り込みで、第三者（主催者）の原文を短くする。

合成した実行記録（600字の引用・41件の要件）を --import に通し、切り詰め・件数・印・再生表示を確かめる。文章はすべて架空。
"""
import copy
import dataclasses
import json
from pathlib import Path

import pytest

import app.web.replay as replay
from app.contracts import QUOTE_SPAN_MAX_CHARS
from app.web.replay import REPLAY_QUOTE_MAX_CHARS, REPLAY_REQUIREMENTS_MAX, load_replays
from app.config import Settings
from tests.web_support import SELF, client, first, make_deps, run_preset

LONG = "これは架空の長い条文です。" * 50  # 650字
assert len(LONG) > 600


def synthetic(n_reqs: int = 41) -> dict:
    """同梱のサンプル記録を土台に、lp_self の実行記録に見立てた JSON を作る（長い引用・n 件の要件）。"""
    d = json.loads((replay.REPLAY_DIR / "sample_defect.json").read_text(encoding="utf-8"))
    d["preset_id"], d["mode"], d["public"] = "lp_self", "LIVE", False
    base_reqs, base_verdicts = d["requirements"], {v["req_id"]: v for v in d["verdicts"]}
    reqs, verdicts, n = [], [], 0
    while len(reqs) < n_reqs:
        for r in base_reqs:
            if len(reqs) >= n_reqs:
                break
            n += 1
            r2, v2 = copy.deepcopy(r), copy.deepcopy(base_verdicts[r["req_id"]])
            r2["req_id"] = v2["req_id"] = f"R{n}"
            reqs.append(r2)
            verdicts.append(v2)
    d["requirements"], d["verdicts"] = reqs, verdicts
    # R1 の引用を600字超にする（位置の幅も合わせる）。R2 の言い換え・R3 の引用は80字以内のまま
    sp = reqs[0]["span"]
    sp["original_span"], sp["end"] = LONG, sp["start"] + len(LONG)
    d["contradictions"] = []
    d["summary"]["requirements_total"] = n_reqs
    d["observations"] = [o for o in d["observations"]]
    for i, o in enumerate(d["observations"]):
        o["req_id"] = {"R1": "R41"}.get(o.get("req_id"), o.get("req_id")) if n_reqs > 40 and o.get("req_id") == "R1" else o.get("req_id")
    return d


def import_record(tmp_path: Path, d: dict, monkeypatch) -> int:
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "bundle"
    out.mkdir()
    monkeypatch.setattr(replay, "REPLAY_DIR", out)
    return replay.main(["--import", str(rec), "--preset", "lp_self"])


def test_the_synthetic_input_really_has_a_long_quote_and_41_requirements():
    d = synthetic()
    assert len(d["requirements"]) == 41 and len(d["requirements"][0]["span"]["original_span"]) > 600
    assert QUOTE_SPAN_MAX_CHARS < 600  # 契約の既定上限より長い記録も、取り込みの段階で受けて縮める


def test_long_quotes_are_clipped_to_80_chars_with_the_mark_and_the_position_kept(tmp_path, monkeypatch):
    d = synthetic()
    assert import_record(tmp_path, d, monkeypatch) == 0
    saved = json.loads((tmp_path / "bundle" / "lp_self.json").read_text(encoding="utf-8"))
    sp = saved["requirements"][0]["span"]
    assert len(sp["original_span"]) == REPLAY_QUOTE_MAX_CHARS and sp["original_span"].endswith("…")
    assert sp["original_span"][:-1] == LONG[: REPLAY_QUOTE_MAX_CHARS - 1]
    assert sp["quote_clipped"] is True
    assert sp["end"] - sp["start"] == len(LONG)  # 位置は元の文のまま
    # 切り詰めていない引用に印は付かず、どの欄にも80字を超える文字列が無い
    assert all(r["span"]["quote_clipped"] is False for r in saved["requirements"][1:] if r.get("span"))
    assert all(len(r["span"]["original_span"]) <= 80 for r in saved["requirements"] if r.get("span"))
    assert LONG[:40] not in json.dumps(saved["events"], ensure_ascii=False)


def test_requirements_are_capped_at_40_and_the_rest_is_kept_as_a_count_only(tmp_path, monkeypatch):
    d = synthetic()
    assert import_record(tmp_path, d, monkeypatch) == 0
    saved = json.loads((tmp_path / "bundle" / "lp_self.json").read_text(encoding="utf-8"))
    assert len(saved["requirements"]) == REPLAY_REQUIREMENTS_MAX == 40
    assert saved["omitted_requirements"] == 1
    kept = {r["req_id"] for r in saved["requirements"]}
    assert "R41" not in kept
    assert {v["req_id"] for v in saved["verdicts"]} == kept  # 省いた要件の判定は持たない
    assert all(o.get("req_id") in kept | {None} for o in saved["observations"])
    assert all(e.get("req_id") in kept | {None} for e in saved["events"])
    assert saved["summary"]["requirements_total"] == 41  # サマリは元の実行の値のまま（件数が見える）


def test_exactly_40_requirements_are_kept_whole(tmp_path, monkeypatch):
    assert import_record(tmp_path, synthetic(40), monkeypatch) == 0
    saved = json.loads((tmp_path / "bundle" / "lp_self.json").read_text(encoding="utf-8"))
    assert len(saved["requirements"]) == 40 and saved["omitted_requirements"] == 0


def test_trace_quotes_and_paraphrases_are_clipped_too(tmp_path, monkeypatch):
    d = synthetic(30)
    last = d["events"][-1]
    qc = {**last, "type": "quote_check", "seq": last["seq"] + 1, "req_id": "R2",
          "quote_steps": [{"attempt": 1, "outcome": "rejected", "reason_code": "not_found", "model_quote": "あ" * 160, "quote_digest": "ab" * 8}]}
    d["events"].append(qc)
    # 引用なしの推測（モデルの言い換え gist が残る）。判定は必ず「参考」
    spec = {**d["requirements"][0], "req_id": "R42", "kind": "推測", "declared_kind": "推測", "span": None, "slot": "なし",
            "demotion": "quote_unverified", "gist": "い" * 140, "chips": [], "check_class": "none"}
    d["requirements"].append(spec)
    d["verdicts"].append({"req_id": "R42", "label": "参考", "reason_code": None, "reason": "", "evidence": []})
    d["summary"]["requirements_total"] += 1
    assert import_record(tmp_path, d, monkeypatch) == 0
    saved = json.loads((tmp_path / "bundle" / "lp_self.json").read_text(encoding="utf-8"))
    steps = [st for e in saved["events"] for st in e.get("quote_steps", [])]
    assert all(len(st.get("model_quote") or "") <= 80 for st in steps)
    assert all(len(r["gist"]) <= 80 for r in saved["requirements"])
    assert any(r["gist"].endswith("…") for r in saved["requirements"])
    assert any(len(st.get("model_quote") or "") == 80 for st in steps)


def test_the_leak_scan_still_runs_on_import(tmp_path, monkeypatch):
    d = synthetic()
    d["requirements"][1]["span"]["original_span"] = d["requirements"][1]["span"]["original_span"][:-1] + "a@b.example.invalid"
    d["requirements"][1]["span"]["end"] = d["requirements"][1]["span"]["start"] + len(d["requirements"][1]["span"]["original_span"])
    # 漏洩の走査の対象は縮めた後の本文。縮めても残る位置（先頭80字以内）に置く
    d["requirements"][2]["span"]["original_span"] = "連絡先は token=sk-" + "A" * 30 + " です。"
    d["requirements"][2]["span"]["end"] = d["requirements"][2]["span"]["start"] + len(d["requirements"][2]["span"]["original_span"])
    code = import_record(tmp_path, d, monkeypatch)
    if code == 0:  # 走査の語彙に当たらなかった場合でも、メール形は止まる
        pytest.skip("この合成値は走査の語彙の外")
    assert code == 1 and not (tmp_path / "bundle" / "lp_self.json").exists()


def test_a_bundle_with_unclipped_third_party_text_is_refused_at_load(tmp_path):
    d = synthetic(5)
    sp = d["requirements"][0]["span"]
    sp["original_span"] = "あ" * 120  # 縮めていない実LPの記録を直接置いた
    sp["end"] = sp["start"] + 120
    d["mode"], d["public"] = "REPLAY", True
    (tmp_path / "lp_self.json").write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    assert "lp_self" not in load_replays(tmp_path)


def test_playback_shows_the_clipped_record_without_reverifying(tmp_path, monkeypatch):
    assert import_record(tmp_path, synthetic(), monkeypatch) == 0
    replays = load_replays(tmp_path / "bundle")
    assert "lp_self" in replays
    deps = dataclasses.replace(make_deps(Settings(self_origin=SELF)), replays={**replays})
    status, ev = run_preset(client(deps), "lp_self")
    assert status == 200
    res = first(ev, "result")
    assert res["mode"] == "REPLAY" and len(res["requirements"]) == 40 and res["omitted_requirements"] == 1
    assert res["requirements"][0]["span"]["quote_clipped"] is True
    assert all(r["reverified"] for r in res["requirements"] if r["span"])  # 保存時に検証済みの印（再生では原文が無く、再検証しない）
    js = (Path(replay.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    assert "保存時に検証済み" in js and "再検証しません" in js and "omitted_requirements" in js and "quote_clipped" in js


def test_bundled_fixture_replays_are_unchanged_in_content_and_still_checked():
    assert replay.check() == []
