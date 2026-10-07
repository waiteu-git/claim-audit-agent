"""REPLAY: 同梱した実行記録（app/web/replay/<preset_id>.json）の読み込みと生成。Vertex・Firestore に依存しない。

同梱の②③は、架空フィクスチャを OracleReader（台本の Reader。実 LLM ではない）＋router でオフライン実行して作った記録で、
記録の reader_model に "oracle-reader" と残る（画面にも出る＝実モデルの実行と偽らない）。実 Gemini の実行記録で置き換える時は
`python -m app.cli <preset> --format json --out rec.json` の出力を `--import` で取り込む（漏洩の走査と契約の検証を通ったものだけ）。
取り込み時は第三者の原文を縮める（引用・言い換え・トレースの引用は1件80字まで、要件は40件まで。clip_for_bundle）。

  python -m app.web.replay --write            # ②③の記録を作り直す（決定論: run_id・時刻・時計を固定）
  python -m app.web.replay --check            # 同梱の記録が生成物と一致するか（tests も確かめる）
  python -m app.web.replay --import rec.json --preset lp_self   # 実行記録を REPLAY として取り込む
"""
import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.agent.planner import InspectMode
from app.agent.run import run_audit
from app.checks.leak_scan import scan_text
from app.config import PRESET_IDS, PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION, PRESETS, Settings
from app.contracts import RunMode, RunRecord, serialize_report
from app.fixtures.eval import OracleReader
from app.fixtures.site import FixtureFetch, FixtureSite
from app.quotes.replay import restore_saved_record

REPLAY_QUOTE_MAX_CHARS = 80  # 同梱する第三者の原文の断片は1件80字まで
REPLAY_REQUIREMENTS_MAX = 40  # 同梱する要件は40件まで（超過分は RunRecord.omitted_requirements に件数だけ残す）
REPLAY_DIR = Path(__file__).resolve().parent / "replay"
FIXTURE_REPLAYS = (PRESET_SAMPLE_DEFECT, PRESET_SAMPLE_INJECTION)
REPLAY_STARTED_AT = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class ReplayBundle:
    preset_id: str
    record: RunRecord
    record_json: str  # serialize_report の出力（再生の result に使う）
    event_jsons: tuple[str, ...]  # 1イベント1行の JSON（None を省く）


def _as_replay(record: RunRecord) -> RunRecord:
    # 契約の検証を通し直す（model_copy は検証しないので、mode・public の書き換えの後に再構成する）
    return record.model_copy(update={"mode": RunMode.REPLAY, "public": True})


def _clip(text: str) -> str:
    return text if len(text) <= REPLAY_QUOTE_MAX_CHARS else text[: REPLAY_QUOTE_MAX_CHARS - 1] + "…"


def clip_for_bundle(saved: str | bytes | RunRecord) -> RunRecord:
    """実行記録を同梱用に縮める（第三者＝主催者の文章を持ち込みすぎない）。取り込み（--import）が必ず通す。

      * 原文の断片を持つ欄（要件の引用 span.original_span・推測の言い換え gist・トレースの棄却された引用 model_quote）は
        80字まで。切り詰めた引用には末尾「…」と span.quote_clipped=true を付ける（位置 start/end は元のまま）。
      * 要件は先頭40件まで。省いた要件の判定・観測・矛盾・イベントも落とし、件数は omitted_requirements に残す。
    切り詰めた後に契約の検証を通し直す（restore_saved_record）。同梱の記録は原文を持たないので、再生時に引用を再検証しない。
    """
    # 契約の検証より前に、保存済みの JSON の段階で縮める（長い原文の記録も受け取れるように）
    d = json.loads(serialize_report(saved) if isinstance(saved, RunRecord) else saved)
    reqs = d["requirements"]
    dropped = {r["req_id"] for r in reqs[REPLAY_REQUIREMENTS_MAX:]}
    d["requirements"] = reqs = reqs[:REPLAY_REQUIREMENTS_MAX]
    for r in reqs:
        sp = r.get("span")
        if sp and len(sp["original_span"]) > REPLAY_QUOTE_MAX_CHARS:
            sp["original_span"] = _clip(sp["original_span"])
            sp["quote_clipped"] = True
        if r.get("gist"):
            r["gist"] = _clip(r["gist"])
    d["verdicts"] = [v for v in d["verdicts"] if v["req_id"] not in dropped]
    d["observations"] = [o for o in d["observations"] if o.get("req_id") not in dropped]
    d["contradictions"] = [c for c in d["contradictions"] if not dropped.intersection(c["req_ids"])]
    events = [e for e in d["events"] if e.get("req_id") not in dropped]
    for e in events:
        for st in e.get("quote_steps") or ():
            if st.get("model_quote"):
                st["model_quote"] = _clip(st["model_quote"])
    d["omitted_events"] = d["omitted_events"] + len(d["events"]) - len(events)
    d["events"] = events
    d["omitted_requirements"] = d.get("omitted_requirements", 0) + len(dropped)
    return restore_saved_record(json.dumps(d, ensure_ascii=False))


def check_bundle_limits(record: RunRecord) -> None:
    """同梱の実行記録（フィクスチャ以外）が、原文の長さと件数の上限を守っているか。守っていない記録は読み込まない。"""
    if len(record.requirements) > REPLAY_REQUIREMENTS_MAX:
        raise ValueError("同梱の記録の要件が上限を超えています")
    for r in record.requirements:
        if r.span is not None and len(r.span.original_span) > REPLAY_QUOTE_MAX_CHARS:
            raise ValueError("同梱の記録の引用が上限を超えています")
        if len(r.gist) > REPLAY_QUOTE_MAX_CHARS:
            raise ValueError("同梱の記録の言い換えが上限を超えています")
    for e in record.events:
        if any(len(st.model_quote or "") > REPLAY_QUOTE_MAX_CHARS for st in e.quote_steps):
            raise ValueError("同梱の記録のトレースの引用が上限を超えています")


def bundle_text(record: RunRecord) -> str:
    return json.dumps(json.loads(serialize_report(_as_replay(record))), ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def leak_findings(text: str) -> dict[str, int]:
    """記録に、公開してはいけない文字列（鍵・メール・内部URL）が無いか。同梱の前に必ず空であること。"""
    return scan_text(text)


def _step_clock(step: float = 0.04):  # noqa: ANN202
    t = [1000.0]

    def clock() -> float:
        t[0] += step
        return t[0]

    return clock


async def build_fixture_record(preset_id: str) -> RunRecord:
    """②③の記録をオフラインで作る（FixtureFetch＋OracleReader＋router。run_id・開始時刻・時計を固定して決定論にする）。"""
    preset = PRESETS[preset_id]
    host = preset.allowed_prefixes[0].host
    fetch = FixtureFetch(FixtureSite.load(), host, preset.allowed_prefixes)
    res = await run_audit(
        preset,
        fetch=fetch,
        reader_model=OracleReader(),
        inspect_mode=InspectMode.ROUTER,
        settings=Settings(),
        run_id=f"replay_{preset_id}",
        clock=_step_clock(),
        started_at=REPLAY_STARTED_AT,
    )
    return res.record


def load_bundle(path: Path) -> ReplayBundle:
    text = path.read_text(encoding="utf-8")
    record = restore_saved_record(text)
    if record.mode is not RunMode.REPLAY or record.preset_id != path.stem:
        raise ValueError("REPLAY の記録ではない、またはプリセットIDがファイル名と合いません")
    if record.preset_id not in FIXTURE_REPLAYS:  # 実LPなど第三者の文章を含みうる記録は、縮めてあることを読み込みの条件にする
        check_bundle_limits(record)
    return ReplayBundle(
        preset_id=record.preset_id,
        record=record,
        record_json=serialize_report(record),
        event_jsons=tuple(e.model_dump_json(exclude_none=True) for e in record.events),
    )


def load_replays(root: Path = REPLAY_DIR) -> dict[str, ReplayBundle]:
    """同梱の記録を全部読む。壊れた記録は載せない（そのプリセットは「保存済みの実行なし」になる）。"""
    out: dict[str, ReplayBundle] = {}
    for p in sorted(root.glob("*.json")) if root.is_dir() else ():
        if p.stem not in PRESET_IDS:
            continue
        try:
            out[p.stem] = load_bundle(p)
        except Exception:  # noqa: BLE001  壊れた同梱物で起動を止めない（再生しないだけ）
            continue
    return out


def check(root: Path = REPLAY_DIR) -> list[str]:
    diff = []
    for pid in FIXTURE_REPLAYS:
        want = bundle_text(asyncio.run(build_fixture_record(pid)))
        p = root / f"{pid}.json"
        if not p.is_file() or p.read_text(encoding="utf-8") != want:
            diff.append(p.name)
    return diff


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.web.replay")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--import", dest="import_path", type=Path)
    ap.add_argument("--preset", choices=PRESET_IDS)
    a = ap.parse_args(argv)
    if a.check:
        diff = check()
        for d in diff:
            print(f"差分: {d}")
        return 1 if diff else 0
    if a.write:
        REPLAY_DIR.mkdir(parents=True, exist_ok=True)
        for pid in FIXTURE_REPLAYS:
            text = bundle_text(asyncio.run(build_fixture_record(pid)))
            if leak_findings(text):
                print(f"{pid}: 記録に公開してはいけない文字列があります", file=sys.stderr)
                return 1
            (REPLAY_DIR / f"{pid}.json").write_text(text, encoding="utf-8")
        return 0
    if not a.preset:
        ap.error("--import には --preset が要ります")
    try:
        record = clip_for_bundle(a.import_path.read_text(encoding="utf-8"))
    except (ValueError, KeyError, TypeError) as e:
        print(f"記録を取り込めません（{type(e).__name__}）", file=sys.stderr)
        return 1
    if record.preset_id != a.preset:
        print("記録のプリセットIDが --preset と合いません", file=sys.stderr)
        return 1
    text = bundle_text(record)
    found = leak_findings(text)
    if found:
        print(f"記録に公開してはいけない文字列があります（種類: {', '.join(sorted(found))}）", file=sys.stderr)
        return 1
    (REPLAY_DIR / f"{a.preset}.json").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
